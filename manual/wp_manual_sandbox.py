#!/usr/bin/env python3
"""Reusable WordPress manual-review sandbox.

Boots a Docker Compose WordPress + MariaDB stack, creates test users for the
default WordPress roles, and installs a wordpress.org plugin by slug.
"""

from __future__ import annotations

import argparse
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from textwrap import dedent
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent
SANDBOX_ROOT = ROOT / "sandboxes"
DEFAULT_PORT_MIN = 8201
DEFAULT_PORT_MAX = 8299
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "password"
DEFAULT_ADMIN_EMAIL = "admin@test.local"
DEFAULT_USERS = [
    ("subscriber_user", "subscriber"),
    ("contributor_user", "contributor"),
    ("author_user", "author"),
    ("editor_user", "editor"),
]


class CommandError(RuntimeError):
    pass


def run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    print(f"$ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.stdout.strip():
        print(proc.stdout.strip())
    if proc.stderr.strip():
        print(proc.stderr.strip(), file=sys.stderr)
    if check and proc.returncode != 0:
        raise CommandError(f"{' '.join(cmd)} exited {proc.returncode}")
    return proc


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise SystemExit("docker is not on PATH")
    run(["docker", "compose", "version"], check=True)


def safe_project_name(slug: str, project: str | None) -> str:
    raw = project or f"manual-wp-{slug}"
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", raw).strip("-").lower()
    if not safe:
        raise SystemExit("project name resolved to empty string")
    return safe[:60]


def validate_slug(slug: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", slug):
        raise SystemExit(
            "plugin slug must look like a wordpress.org slug, e.g. quiz-maker",
        )
    return slug


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def choose_port(requested: int | None, *, allow_occupied: bool = False) -> int:
    if requested is not None:
        if not allow_occupied and not port_is_free(requested):
            raise SystemExit(f"port {requested} is already in use")
        return requested
    for port in range(DEFAULT_PORT_MIN, DEFAULT_PORT_MAX + 1):
        if port_is_free(port):
            return port
    raise SystemExit(f"no free port in {DEFAULT_PORT_MIN}-{DEFAULT_PORT_MAX}")


def write_compose(workdir: Path, *, port: int, wp_url: str, wordpress_image: str, db_image: str) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    compose = f"""
services:
  db:
    image: {db_image}
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wpuser
      MYSQL_PASSWORD: wppass
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 5s
      timeout: 5s
      retries: 20

  wordpress:
    image: {wordpress_image}
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "{port}:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wpuser
      WORDPRESS_DB_PASSWORD: wppass
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_DEBUG: "1"
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_DEBUG_LOG', true);
        define('WP_DEBUG_DISPLAY', false);
        define('SAVEQUERIES', true);
      WP_URL: "{wp_url}"
      WP_TITLE: "Manual WP Review"
      WP_ADMIN_USER: "{DEFAULT_ADMIN_USER}"
      WP_ADMIN_PASS: "{DEFAULT_ADMIN_PASS}"
      WP_ADMIN_EMAIL: "{DEFAULT_ADMIN_EMAIL}"
    volumes:
      - wp_data:/var/www/html
      - ./wp-init.sh:/docker-entrypoint.d/99-wp-init.sh

volumes:
  wp_data:
"""
    (workdir / "docker-compose.yml").write_text(dedent(compose).lstrip(), encoding="utf-8")

    init = """#!/usr/bin/env bash
set -eu

WP_PATH="${WP_PATH:-/var/www/html}"
WP_URL="${WP_URL:-http://localhost:8201}"
WP_TITLE="${WP_TITLE:-Manual WP Review}"
WP_ADMIN_USER="${WP_ADMIN_USER:-admin}"
WP_ADMIN_PASS="${WP_ADMIN_PASS:-password}"
WP_ADMIN_EMAIL="${WP_ADMIN_EMAIL:-admin@test.local}"

if ! command -v wp >/dev/null 2>&1; then
    echo "[wp-init] installing wp-cli"
    if ! command -v curl >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y --no-install-recommends curl ca-certificates >/dev/null
    fi
    curl -sSLo /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x /usr/local/bin/wp
fi

for _ in $(seq 1 60); do
    if php -r '$m = mysqli_init(); exit(mysqli_real_connect($m, getenv("WORDPRESS_DB_HOST"), getenv("WORDPRESS_DB_USER"), getenv("WORDPRESS_DB_PASSWORD"), getenv("WORDPRESS_DB_NAME")) ? 0 : 1);' >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if wp --allow-root --path="$WP_PATH" core is-installed >/dev/null 2>&1; then
    echo "[wp-init] core already installed"
    exit 0
fi

echo "[wp-init] installing WordPress"
wp --allow-root --path="$WP_PATH" core install \\
    --url="$WP_URL" \\
    --title="$WP_TITLE" \\
    --admin_user="$WP_ADMIN_USER" \\
    --admin_password="$WP_ADMIN_PASS" \\
    --admin_email="$WP_ADMIN_EMAIL" \\
    --skip-email
"""
    init_path = workdir / "wp-init.sh"
    init_path.write_text(init, encoding="utf-8")
    init_path.chmod(0o755)


def compose(project: str, workdir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["docker", "compose", "-p", project, *args], cwd=workdir, check=check)


def wp(project: str, workdir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return compose(
        project,
        workdir,
        "exec",
        "-T",
        "wordpress",
        "env",
        "HTTP_HOST=localhost",
        "wp",
        "--allow-root",
        *args,
        check=check,
    )


def sh(project: str, workdir: Path, command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return compose(project, workdir, "exec", "-T", "wordpress", "sh", "-lc", command, check=check)


def wait_http(url: str, timeout: int) -> None:
    deadline = time.time() + timeout
    login_url = f"{url}/wp-login.php"
    while time.time() < deadline:
        try:
            with urlopen(login_url, timeout=5) as resp:
                if resp.status in (200, 302):
                    return
        except Exception:
            time.sleep(2)
    raise TimeoutError(f"WordPress did not answer at {login_url} within {timeout}s")


def ensure_wp_cli(project: str, workdir: Path) -> None:
    exists = sh(project, workdir, "command -v wp >/dev/null 2>&1", check=False)
    if exists.returncode == 0:
        return
    sh(
        project,
        workdir,
        "if ! command -v curl >/dev/null 2>&1; then "
        "apt-get update -qq && "
        "apt-get install -y --no-install-recommends curl ca-certificates >/dev/null; "
        "fi; "
        "if ! command -v wp >/dev/null 2>&1; then "
        "curl -sSLo /usr/local/bin/wp "
        "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && "
        "chmod +x /usr/local/bin/wp; "
        "fi",
    )


def wait_db(project: str, workdir: Path, timeout: int) -> None:
    deadline = time.time() + timeout
    probe = (
        "php -r '$m = mysqli_init(); "
        "exit(mysqli_real_connect($m, getenv(\"WORDPRESS_DB_HOST\"), "
        "getenv(\"WORDPRESS_DB_USER\"), getenv(\"WORDPRESS_DB_PASSWORD\"), "
        "getenv(\"WORDPRESS_DB_NAME\")) ? 0 : 1);'"
    )
    while time.time() < deadline:
        proc = sh(project, workdir, probe, check=False)
        if proc.returncode == 0:
            return
        time.sleep(2)
    raise TimeoutError(f"WordPress database did not become ready within {timeout}s")


def install_wordpress_core(project: str, workdir: Path, url: str) -> None:
    installed = wp(project, workdir, "core", "is-installed", check=False)
    if installed.returncode == 0:
        return
    wp(
        project,
        workdir,
        "core",
        "install",
        f"--url={url}",
        "--title=Manual WP Review",
        f"--admin_user={DEFAULT_ADMIN_USER}",
        f"--admin_password={DEFAULT_ADMIN_PASS}",
        f"--admin_email={DEFAULT_ADMIN_EMAIL}",
        "--skip-email",
    )


def wait_wp(project: str, workdir: Path, timeout: int) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = wp(project, workdir, "core", "is-installed", check=False)
        if proc.returncode == 0:
            return
        time.sleep(2)
    raise TimeoutError(f"WordPress core install did not complete within {timeout}s")


def create_users(project: str, workdir: Path) -> None:
    for login, role in DEFAULT_USERS:
        exists = wp(project, workdir, "user", "list", f"--login={login}", "--field=ID", check=False)
        if exists.stdout.strip():
            wp(project, workdir, "user", "update", login, f"--role={role}", check=False)
            continue
        wp(
            project,
            workdir,
            "user",
            "create",
            login,
            f"{login}@test.local",
            f"--role={role}",
            "--user_pass=password",
        )


def install_plugin(project: str, workdir: Path, slug: str, version: str | None) -> None:
    args = ["plugin", "install", slug, "--activate", "--force"]
    if version:
        args.append(f"--version={version}")
    wp(project, workdir, *args)
    fire_admin_init(project, workdir)


def fire_admin_init(project: str, workdir: Path) -> None:
    login = (
        "curl -s -c /tmp/manual_wp_cookies.txt "
        "-d 'log=admin&pwd=password&wp-submit=Log+In&testcookie=1' "
        "-b 'wordpress_test_cookie=WP+Cookie+check' "
        "http://localhost/wp-login.php -o /dev/null"
    )
    visit = (
        "curl -s -b /tmp/manual_wp_cookies.txt "
        "http://localhost/wp-admin/ -o /dev/null -w '%{http_code}'"
    )
    sh(project, workdir, login, check=False)
    sh(project, workdir, visit, check=False)


def print_summary(*, url: str, slug: str, project: str, workdir: Path) -> None:
    print("\nSandbox ready")
    print(f"URL:      {url}")
    print(f"Plugin:   {slug}")
    print(f"Project:  {project}")
    print(f"Workdir:  {workdir}")
    print("\nAccounts")
    print(f"  admin / {DEFAULT_ADMIN_PASS} (administrator)")
    for login, role in DEFAULT_USERS:
        print(f"  {login} / password ({role})")
    print("\nUseful commands")
    print(f"  docker compose -p {project} -f {workdir / 'docker-compose.yml'} logs -f wordpress")
    print(f"  docker compose -p {project} -f {workdir / 'docker-compose.yml'} down -v")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Boot a WordPress manual-review sandbox and install a plugin by slug.",
    )
    parser.add_argument("--plugin-slug", required=True, help="wordpress.org plugin slug to install")
    parser.add_argument("--plugin-version", help="optional plugin version to install")
    parser.add_argument("--port", type=int, help="host port for WordPress; defaults to first free 8201-8299")
    parser.add_argument("--project", help="Docker Compose project name; defaults to manual-wp-<slug>")
    parser.add_argument("--wordpress-image", default="wordpress:latest")
    parser.add_argument("--db-image", default="mariadb:10.11")
    parser.add_argument("--timeout", type=int, default=240, help="startup timeout in seconds")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="run docker compose down -v for the project before booting",
    )
    parser.add_argument(
        "--down",
        action="store_true",
        help="tear down the project and exit; still requires --plugin-slug to derive default project",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    slug = validate_slug(args.plugin_slug)
    project = safe_project_name(slug, args.project)
    port = (
        choose_port(args.port, allow_occupied=args.reset or args.down)
        if not args.down else (args.port or DEFAULT_PORT_MIN)
    )
    url = f"http://localhost:{port}"
    workdir = SANDBOX_ROOT / project

    require_docker()
    write_compose(
        workdir,
        port=port,
        wp_url=url,
        wordpress_image=args.wordpress_image,
        db_image=args.db_image,
    )

    if args.down or args.reset:
        compose(project, workdir, "down", "-v", "--remove-orphans", check=False)
        if args.down:
            print(f"Stopped project {project}")
            return 0

    compose(project, workdir, "up", "-d")
    wait_http(url, args.timeout)
    ensure_wp_cli(project, workdir)
    wait_db(project, workdir, args.timeout)
    install_wordpress_core(project, workdir, url)
    wait_wp(project, workdir, args.timeout)
    create_users(project, workdir)
    install_plugin(project, workdir, slug, args.plugin_version)
    print_summary(url=url, slug=slug, project=project, workdir=workdir)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CommandError, TimeoutError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
