#!/usr/bin/env bash
set -euo pipefail

EXPECTED_NARGO_VERSION="1.0.0-beta.22"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECTS_DIR="${SCRIPT_DIR}/noir_projects"

if ! command -v nargo >/dev/null 2>&1; then
    echo "error: 'nargo' not found on PATH" >&2
    exit 1
fi

if ! command -v sunspot >/dev/null 2>&1; then
    echo "error: 'sunspot' not found on PATH" >&2
    exit 1
fi

actual_nargo_version="$(nargo --version | sed -n 's/^nargo version = //p' | head -n 1)"
if [[ "${actual_nargo_version}" != "${EXPECTED_NARGO_VERSION}" ]]; then
    echo "error: nargo version mismatch (expected ${EXPECTED_NARGO_VERSION}, got ${actual_nargo_version:-unknown})" >&2
    exit 1
fi

if [[ ! -d "${PROJECTS_DIR}" ]]; then
    echo "error: noir_projects directory not found at ${PROJECTS_DIR}" >&2
    exit 1
fi

shopt -s nullglob
found_any=0
failed_projects=()

for project_dir in "${PROJECTS_DIR}"/*/; do
    project_dir="${project_dir%/}"
    nargo_toml="${project_dir}/Nargo.toml"
    if [[ ! -f "${nargo_toml}" ]]; then
        continue
    fi

    found_any=1
    project_name="$(basename "${project_dir}")"
    echo "=== ${project_name} ==="

    if ! (
        set -e
        cd "${project_dir}"

        run_step() {
            local label="$1"; shift
            local output
            if ! output="$("$@" 2>&1)"; then
                echo "error: ${label} failed" >&2
                printf '%s\n' "${output}" >&2
                return 1
            fi
        }

        run_step "nargo compile" nargo compile

        json_files=(target/*.json)
        if [[ "${#json_files[@]}" -eq 0 ]]; then
            echo "error: nargo compile produced no ACIR JSON in ${project_dir}/target" >&2
            exit 1
        fi
        acir_file="${json_files[0]}"

        run_step "sunspot compile" sunspot compile "${acir_file}"

        ccs_file="${acir_file%.json}.ccs"
        if [[ ! -f "${ccs_file}" ]]; then
            echo "error: sunspot compile did not produce ${ccs_file}" >&2
            exit 1
        fi

        run_step "sunspot setup" sunspot setup "${ccs_file}"

        if [[ -f "Prover.toml" ]]; then
            run_step "nargo execute" nargo execute
        fi
    ); then
        echo "error: nargo execute failed for ${project_name}" >&2
        failed_projects+=("${project_name}")
    fi
done

if [[ "${found_any}" -eq 0 ]]; then
    echo "warning: no projects with Nargo.toml found under ${PROJECTS_DIR}" >&2
fi

if [[ "${#failed_projects[@]}" -gt 0 ]]; then
    echo "error: ${#failed_projects[@]} project(s) failed: ${failed_projects[*]}" >&2
    exit 1
fi
