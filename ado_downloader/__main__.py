#!/usr/bin/env python3
import argparse
import coloredlogs
import dataclasses
import datetime
import json
import logging
import os
import re
import requests
import shutil
import subprocess
import sys
import tempfile
import tqdm
import typing
import urllib.parse
import yaml
import zipfile

from colorama import Fore, Style
from typing import Any, Dict, Optional, Sequence, Union

coloredlogs.DEFAULT_LEVEL_STYLES["debug"]["color"] = "black"

coloredlogs.install(
    level="INFO",
    fmt="%(levelname)s %(message)s",
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class FileOrDir:
    name: str
    is_file: bool
    output_name: Union[str, None] = None


def main() -> None:
    az_command = shutil.which("az")
    if not az_command:
        logger.error("you must first install the az cli")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--all-artifacts",
        dest="all_artifacts",
        action="store_true",
        default=False,
        help="Download all artifacts",
    )
    parser.add_argument(
        "-n", "--artifact-name", dest="artifact_names", help="Artifact name", action="append"
    )
    parser.add_argument(
        "-f",
        "--artifact-manifest",
        dest="artifact_manifest",
        help="Path to file specifying artifacts to download",
    )
    parser.add_argument(
        "-o", "--output-dir", dest="output_dir", help="Output dir", default="."
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=False,
        help="Find artifacts but do not download",
    )
    parser.add_argument(
        "--skip-existing",
        dest="skip_existing",
        action="store_true",
        default=False,
        help="Skip downloading files existing in output dir",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Enable verbose output",
    )

    build_filter_group = parser.add_mutually_exclusive_group()
    build_filter_group.add_argument(
        "--build-id", dest="build_id", help="Specific ID of build to use", type=int
    )
    build_filter_group.add_argument(
        "--build-branch", dest="build_branch", help="Source branch to filter builds on"
    )

    args = parser.parse_args()

    if args.verbose:
        coloredlogs.increase_verbosity()

    if args.artifact_manifest:
        if not os.path.isfile(args.artifact_manifest):
            logger.error("cannot find artifact manifest specified")
            sys.exit(1)
        with open(args.artifact_manifest) as f:
            artifact_sources = yaml.safe_load(f)
    else:
        # Find config file
        artifact_sources_file_path = "ado-download.yaml"

        if not os.path.isfile(artifact_sources_file_path):
            logger.error("cannot find ado-download.yaml")
            sys.exit(1)
        with open(artifact_sources_file_path) as f:
            artifact_sources = yaml.safe_load(f)

    if args.artifact_names:
        if args.all_artifacts:
            logger.error(
                "Can't specify --all-artifacts (or -a) and --artifact-name (or -n) together"
            )
            sys.exit(1)

        unknown_artifact_name = False
        for name in args.artifact_names:
            if name not in artifact_sources["artifacts"]:
                logger.error(f"unknown artifact: {name}")
                unknown_artifact_name = True

        if unknown_artifact_name:
            logger.info("Possible artifacts:")
            for artifact_name in artifact_sources["artifacts"]:
                logger.info(f"  {artifact_name}")

            sys.exit(1)

        artifact_names = args.artifact_names
    elif args.all_artifacts:
        artifact_names = list(artifact_sources["artifacts"].keys())
    else:
        logger.info(
            "No artifact specified; please specify an artifact name using --artifact-name (or -n)"
        )
        logger.info("The following artifacts are available by default:")
        for artifact_name in artifact_sources["artifacts"]:
            logger.info(f"  {artifact_name}")
        sys.exit(0)

    pipelines_to_resolve = set()
    for requested_artifact in artifact_names:
        artifact_info = artifact_sources["artifacts"][requested_artifact]
        pipelines_to_resolve.add(artifact_info["pipeline"])

    selected_runs_by_pipeline = {}
    for pipeline in pipelines_to_resolve:
        selected_runs_by_pipeline[pipeline] = select_pipeline_run(
            artifact_sources, pipeline, args.build_branch, args.build_id
        )

    output_location = args.output_dir
    logger.info(f"Downloading to: {output_location}")

    for requested_artifact in artifact_names:
        artifact_info = artifact_sources["artifacts"][requested_artifact]

        pipeline_name = artifact_info["pipeline"]
        pipeline = artifact_sources["pipelines"][pipeline_name]

        run_id = selected_runs_by_pipeline[pipeline_name]

        for artifact in artifact_info["pipeline-artifacts"]:
            artifact_name = artifact["name"]

            logger.info(
                f"Downloading: "
                f"[{Fore.BLUE}{Style.BRIGHT}{requested_artifact}{Style.RESET_ALL}]..."
            )

            logger.debug("Retrieving token from az cli...")

            bearer_token_cmd = [
                az_command,
                "account",
                "get-access-token",
                "--resource=https://management.core.windows.net/",
            ]

            bearer_token_proc = subprocess.run(
                bearer_token_cmd, capture_output=True, stdin=subprocess.DEVNULL
            )
            if bearer_token_proc.returncode != 0:
                logger.error(
                    "failed to get Azure access token; details follow.")
                logger.error(bearer_token_proc.stderr.decode("utf-8"))
                sys.exit(1)

            bearer_token_stdout = bearer_token_proc.stdout.decode(
                "utf-8").strip()
            if not bearer_token_stdout:
                logger.error("failed to get Azure access token")
                sys.exit(1)

            bearer_token = json.loads(bearer_token_stdout)

            logger.debug("Querying artifact info from Azure DevOps...")

            ado_org = artifact_sources["defaults"]["ado-org"]
            ado_project = artifact_sources["defaults"]["ado-project"]

            list_artifacts_cmd = [
                az_command,
                "pipelines",
                "runs",
                "artifact",
                "list",
                "--org",
                ado_org,
                "--project",
                ado_project,
                "--run-id",
                str(run_id),
            ]

            list_artifacts_proc = subprocess.run(
                list_artifacts_cmd, capture_output=True, stdin=subprocess.DEVNULL
            )
            if list_artifacts_proc.returncode != 0:
                logger.error(
                    "failed to list Azure DevOps artifacts; details follow.")
                logger.error(list_artifacts_proc.stderr.decode("utf-8"))
                sys.exit(1)

            list_artifacts_stdout = list_artifacts_proc.stdout.decode(
                "utf-8").strip()
            if not list_artifacts_stdout:
                logger.error("unable to find artifacts")
                sys.exit(1)

            found_artifacts = json.loads(list_artifacts_stdout)

            logger.debug(f"Found info on {len(found_artifacts)} artifacts.")

            found_artifact = None
            for a in found_artifacts:
                if a["name"] == artifact_name:
                    found_artifact = a
                    break

            if not found_artifact:
                logger.error(
                    f"failed to find artifact {artifact_name} in pipeline")
                sys.exit(1)

            artifact_type = found_artifact["resource"]["type"]
            artifact_is_container = artifact_type == "Container"

            if artifact_is_container:
                data_prop = found_artifact["resource"]["data"].removeprefix(
                    "#/")
                artifact_download_uri = (
                    f"{ado_org}/_apis/resources/Containers/{data_prop}"
                )
            else:
                artifact_download_uri = found_artifact["resource"]["downloadUrl"]

            access_token = bearer_token["accessToken"]
            download_headers = {"Authorization": f"Bearer {access_token}"}

            things_to_dl = []

            if "files" in artifact:
                for item in artifact["files"]:
                    things_to_dl.append(parse_file_or_dir(item, True))
            if "dirs" in artifact:
                for item in artifact["dirs"]:
                    things_to_dl.append(parse_file_or_dir(item, False))

            for item in things_to_dl:
                resource_name = item.name
                is_file = item.is_file

                resource_download_uri = artifact_download_uri

                if artifact_is_container:
                    resource_download_uri += "?itemPath=" + urllib.parse.quote_plus(
                        artifact_name + "/" + resource_name
                    )
                    if not is_file:
                        resource_download_uri += "&%24format=zip&saveAbsolutePath=false"
                else:
                    if is_file:
                        resource_download_uri = resource_download_uri.replace(
                            "format=zip", "format=file"
                        )

                    resource_download_uri += "&subPath=" + urllib.parse.quote_plus(
                        resource_name
                    )

                if is_file:
                    if item.output_name:
                        dest_filename = item.output_name
                    else:
                        resource_name_without_leading_separator = (
                            resource_name[1:]
                            if resource_name.startswith("/")
                            else resource_name
                        )

                        dest_filename = resource_name_without_leading_separator

                    if "preserve-dirs" in artifact and artifact["preserve-dirs"]:
                        dest_path = os.path.join(
                            output_location, dest_filename
                        )
                    else:
                        dest_path = os.path.join(
                            output_location,
                            os.path.basename(
                                dest_filename),
                        )

                    if os.path.isfile(dest_path) and args.skip_existing:
                        logger.info(
                            f"  Skipping file download; destination exists: {dest_path}"
                        )
                        continue
                else:
                    dest_path = None

                if args.dry_run:
                    logger.info(
                        f"  Dry run only; would download "
                        f"{'file' if is_file else 'dir'} "
                        f"[{artifact_name}]{resource_name}"
                    )
                    logger.debug(f"    (uri: {resource_download_uri})")
                    continue

                r = requests.get(
                    resource_download_uri, headers=download_headers, stream=True
                )
                if not r.ok:
                    logger.error(
                        f"failed to download artifact: {artifact_name} "
                        f"(resource='{resource_name}')"
                    )
                    sys.exit(1)

                block_size = 64 * 1024
                total_size_in_bytes = int(r.headers.get("content-length", 0))
                resource_base_name = os.path.basename(resource_name)
                progress_bar = tqdm.tqdm(
                    total=total_size_in_bytes,
                    unit="iB",
                    unit_scale=True,
                    desc=f"{'File' if is_file else 'Dir'} [{artifact_name}]{resource_base_name}",
                )

                if is_file:
                    assert dest_path is not None

                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

                    completed = False

                    try:
                        with open(dest_path, "wb") as dest_file:
                            for data in r.iter_content(block_size):
                                progress_bar.update(len(data))
                                dest_file.write(data)
                            r.close()
                            dest_file.flush()
                            completed = True
                    finally:
                        if not completed and os.path.exists(dest_path):
                            os.remove(dest_path)

                    progress_bar.close()
                else:
                    with tempfile.NamedTemporaryFile() as temp_file:
                        for data in r.iter_content(block_size):
                            progress_bar.update(len(data))
                            temp_file.write(data)

                        temp_file.flush()
                        r.close()

                        progress_bar.close()

                        with zipfile.ZipFile(temp_file.name) as zipped_file:
                            for member_info in zipped_file.infolist():
                                if member_info.is_dir():
                                    continue

                                filename = member_info.filename

                                # Strip the leading slash
                                if filename.startswith("/") or filename.startswith(
                                    "\\"
                                ):
                                    filename = filename[1:]

                                # If present, strip off the name of the artifact
                                if filename.startswith(artifact_name):
                                    len_to_strip = len(artifact_name)
                                    filename = filename[len_to_strip:]

                                # Strip any additional leading slash
                                if filename.startswith("/") or filename.startswith(
                                    "\\"
                                ):
                                    filename = filename[1:]

                                logger.info(f"  Extracting file: {filename}")

                                dest_path = os.path.join(
                                    output_location, filename)

                                os.makedirs(os.path.dirname(
                                    dest_path), exist_ok=True)

                                with zipped_file.open(member_info, "r") as source_file:
                                    completed = False

                                    try:
                                        with open(dest_path, "wb") as dest_file:
                                            shutil.copyfileobj(
                                                source_file, dest_file)
                                            dest_file.flush()
                                            completed = True
                                    finally:
                                        if not completed and os.path.exists(dest_path):
                                            os.remove(dest_path)


def select_pipeline_run(
    artifact_sources: Any,
    pipeline_name: str,
    forced_build_branch: Optional[str],
    forced_build_id: Optional[int],
) -> int:
    az_command = shutil.which("az")
    pipeline = artifact_sources["pipelines"][pipeline_name]
    allowed_build_reasons = artifact_sources.get("allowedBuildReasons")

    ado_org = artifact_sources["defaults"]["ado-org"]
    ado_project = artifact_sources["defaults"]["ado-project"]
    ado_pipeline_id = pipeline["pipeline-id"]

    if forced_build_id is None:
        list_builds_cmd = [
            az_command,
            "pipelines",
            "runs",
            "list",
            "--org",
            ado_org,
            "--project",
            ado_project,
            "--pipeline-ids",
            str(ado_pipeline_id),
            "--branch",
            forced_build_branch or pipeline["default-branch"],
            "--result",
            "succeeded",
            "--status",
            "completed",
            "--query-order",
            "FinishTimeDesc",
            "--top",
            "100",
        ]

        logger.info(
            f"Selecting run for pipeline '{Fore.GREEN}{pipeline_name}{Style.RESET_ALL}'..."
        )

        logger.debug("Querying Azure DevOps for pipeline info...")

        list_builds_result_proc = subprocess.run(
            list_builds_cmd, capture_output=True, stdin=subprocess.DEVNULL
        )
        if list_builds_result_proc.returncode != 0:
            logger.error(
                "unable to find Azure DevOps pipelines; details follow.")
            logger.error(list_builds_result_proc.stderr.decode("utf-8"))
            sys.exit(1)

        list_builds_result_stdout = list_builds_result_proc.stdout.decode(
            "utf-8"
        ).strip()
        if not list_builds_result_stdout:
            logger.error("unable to find successful pipeline run")
            sys.exit(1)

        list_builds_result = json.loads(list_builds_result_stdout)

        logger.debug(
            f"Retrieved info on {len(list_builds_result)} pipeline runs; filtering..."
        )

        if "tag-patterns" in pipeline:
            required_tag_patterns = [re.compile(
                p) for p in pipeline["tag-patterns"]]
        else:
            required_tag_patterns = []

        def matches_needs(
            patterns: Sequence[typing.Pattern[str]], br: Dict[str, Any]
        ) -> bool:

            if allowed_build_reasons is not None and \
                    br["reason"] not in allowed_build_reasons:
                return False

            if patterns:
                for pattern in patterns:
                    found = False
                    for actual_tag in br["tags"]:
                        if pattern.fullmatch(actual_tag):
                            found = True
                            break

                    if not found:
                        return False

            return True

        filtered_build_results = list(
            [
                br
                for br in list_builds_result
                if matches_needs(required_tag_patterns, br)
            ]
        )

        if not filtered_build_results:
            logger.error(
                "unable to find successful pipeline run with appropriate reason"
            )
            sys.exit(1)

        logger.debug(
            f"Found {len(filtered_build_results)} pipeline runs that match our criteria."
        )

        build_result = filtered_build_results[0]
    else:
        show_build_cmd = [
            az_command,
            "pipelines",
            "runs",
            "show",
            "--org",
            ado_org,
            "--project",
            ado_project,
            "--id",
            str(forced_build_id),
        ]

        logger.info(f"Querying build ID: {forced_build_id}")

        show_build_result_proc = subprocess.run(
            show_build_cmd, capture_output=True, stdin=subprocess.DEVNULL
        )
        if show_build_result_proc.returncode != 0:
            logger.error(
                f"unable to query Azure DevOps build with ID {forced_build_id}; "
                "details follow."
            )
            logger.error(show_build_result_proc.stderr.decode("utf-8"))
            sys.exit(1)

        build_result = json.loads(
            show_build_result_proc.stdout.decode("utf-8").strip())

        actual_ado_pipeline_id = int(build_result["definition"]["id"])
        if actual_ado_pipeline_id != ado_pipeline_id:
            logger.error(
                f"the specified build is associated with pipeline "
                f"definition {actual_ado_pipeline_id} (expected: {ado_pipeline_id})"
            )
            sys.exit(1)

    run_id = build_result["id"]
    tags = build_result["tags"]

    finish_time_str = build_result["finishTime"]

    finish_time_utc = datetime.datetime.strptime(
        finish_time_str, "%Y-%m-%dT%H:%M:%S.%f%z"
    )
    now_time_utc = datetime.datetime.now(datetime.timezone.utc)

    total_hours_ago = (now_time_utc - finish_time_utc).total_seconds() // 3600
    days_ago = int(total_hours_ago // 24)
    hours_ago = int(total_hours_ago % 24)

    pipeline_def_name = build_result["definition"]["name"]

    run_branch = build_result["sourceBranch"]
    if run_branch.startswith("refs/heads"):
        run_branch = run_branch[11:]

    run_source_ver = build_result["sourceVersion"]

    run_result = build_result["result"]
    run_reason = build_result["reason"]

    if run_result == "succeeded":
        run_result = f"{Fore.GREEN}{run_result}{Style.RESET_ALL}"

    logger.info(
        f"Found {Fore.CYAN}{Style.BRIGHT}{pipeline_def_name}{Style.RESET_ALL} pipeline run "
        f"{Fore.CYAN}{Style.BRIGHT}{run_id}{Style.RESET_ALL}: "
        f"finished {Fore.YELLOW}{days_ago} day(s), {hours_ago} hour(s) ago{Style.RESET_ALL}."
    )
    logger.info(
        f"  - {run_result} build / branch {Fore.YELLOW}{run_branch}{Style.RESET_ALL}"
    )
    logger.info(f"  - commit {Fore.BLUE}{run_source_ver}{Style.RESET_ALL}")
    logger.info(f"  - {Fore.YELLOW}{run_reason}{Style.RESET_ALL} trigger")
    logger.info(
        f"  - tags {Fore.MAGENTA}{' '.join([f'[{tag}]' for tag in tags])}{Style.RESET_ALL}"
    )

    return int(run_id)


def parse_file_or_dir(item: Any, is_file: bool) -> FileOrDir:
    if isinstance(item, str):
        return FileOrDir(name=str(item), is_file=is_file)

    return FileOrDir(name=item["name"], output_name=item.get("output-name"), is_file=is_file)
