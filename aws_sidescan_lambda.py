"""Agentless AWS Lambda artifact side-scan (LMB-07 vulnerable-dependency detection).

Pure core: LambdaArtifactExtractor presents a Lambda function's deployment zip
(-> /var/task) and its layer zips (-> /opt) as a merged FilesystemExtractor, so the
UNCHANGED aws_sidescan pipeline (collect_app_packages -> match_vulns) finds vulnerable
dependencies with zero AWS and zero disk. The ONLY live step is fetch_lambda_artifact,
which takes an injected http_get so orchestration stays fully mock-testable.
"""
import io
import zipfile
from typing import Callable, Dict, List, Optional, Tuple

from aws_sidescan import DictExtractor, _norm_tar_path


class LambdaArtifactUnavailable(Exception):
    """Raised when a Lambda artifact cannot be fetched/decoded (never a false-clean)."""


def merge_lambda_artifact(function_zip: Optional[bytes], layer_zips=(), *,
                          max_file_bytes: int = 5_000_000,
                          max_total_bytes: int = 300_000_000,
                          notes: Optional[List[str]] = None) -> Dict[str, bytes]:
    """Unzip the function code under /var/task and each layer under /opt (later layers
    overwrite earlier, mirroring the Lambda runtime) into a merged path->bytes map.
    PURE and fail-open: a bad zip / oversize entry becomes a note, never a crash."""
    merged: Dict[str, bytes] = {}
    total = 0

    def _add(blob: Optional[bytes], prefix: str):
        nonlocal total
        if not blob:
            return
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except Exception as e:
            if notes is not None:
                notes.append(f"lambda artifact unreadable: {e}")
            return
        try:
            infos = zf.infolist()
        except Exception:
            infos = []
        for info in infos:
            try:
                if info.is_dir():
                    continue
                rel = _norm_tar_path(info.filename)      # strip ./, leading /, reject ..
                if not rel:
                    continue
                if info.file_size > max_file_bytes or total > max_total_bytes:
                    continue
                data = zf.read(info)
                if len(data) > max_file_bytes:
                    continue
                merged[prefix + "/" + rel] = data
                total += len(data)
            except Exception:
                continue

    _add(function_zip, "/var/task")
    for lz in (layer_zips or ()):
        _add(lz, "/opt")
    return merged


class LambdaArtifactExtractor(DictExtractor):
    """FilesystemExtractor over a Lambda function zip + its layer zips. Subclasses
    DictExtractor so read_file/exists/walk/stat are the already-validated pure
    implementations — the artifact scans byte-identically to the test double."""

    def __init__(self, function_zip: Optional[bytes], layer_zips=(), *,
                 notes: Optional[List[str]] = None, **caps):
        super().__init__(merge_lambda_artifact(function_zip, layer_zips, notes=notes, **caps))


def fetch_lambda_artifact(lmb_client, function_name: str, *,
                          http_get: Callable[[str], bytes],
                          max_bytes: int = 300_000_000,
                          notes: Optional[List[str]] = None
                          ) -> Tuple[Optional[bytes], List[bytes], Optional[str]]:
    """LIVE seam (the only network step): resolve a function's code zip + layer zips.
    Returns (function_zip, layer_zips, package_type). PackageType=='Image' returns
    (None, [], 'Image') so the caller routes to the ECR image path. Both lmb_client
    and http_get are injected so this is fully mock-testable; production http_get is a
    ~5-line urllib.request wrapper with a byte cap + timeout (no new dependency)."""
    try:
        resp = lmb_client.get_function(FunctionName=function_name)
    except Exception as e:
        raise LambdaArtifactUnavailable(f"get_function failed: {e}")
    cfg = resp.get("Configuration", {}) or {}
    if cfg.get("PackageType") == "Image":
        return None, [], "Image"
    code_url = (resp.get("Code", {}) or {}).get("Location")
    function_zip = None
    if code_url:
        try:
            function_zip = http_get(code_url)
        except Exception as e:
            if notes is not None:
                notes.append(f"lambda code download failed: {e}")
    layer_zips: List[bytes] = []
    for layer in cfg.get("Layers", []) or []:
        arn = layer.get("Arn") if isinstance(layer, dict) else None
        if not arn:
            continue
        try:
            lv = lmb_client.get_layer_version_by_arn(Arn=arn)
            loc = (lv.get("Content", {}) or {}).get("Location")
            if loc:
                layer_zips.append(http_get(loc))
        except Exception as e:
            if notes is not None:
                notes.append(f"lambda layer download failed ({arn}): {e}")
    return function_zip, layer_zips, cfg.get("PackageType", "Zip")
