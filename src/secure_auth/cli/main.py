"""Administrative and operational CLI for the Secure Authentication Service."""

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlmodel import Session, col, select

from secure_auth.config.settings import settings
from secure_auth.core.exceptions import UserAlreadyExistsError
from secure_auth.models.user import User
from secure_auth.services.audit_service import AuditService
from secure_auth.services.auth_service import AuthService
from secure_auth.storage.database import get_engine, init_db
from secure_auth.storage.repository import UserRepository

console = Console()

app = typer.Typer(
    name="secure-auth",
    help="Defensive cybersecurity authentication service & management CLI.",
    add_completion=False,
)
user_app = typer.Typer(help="User account administration commands.")
audit_app = typer.Typer(help="Security audit trail inspection commands.")
db_app = typer.Typer(help="Database administration commands.")

app.add_typer(user_app, name="user")
app.add_typer(audit_app, name="audit")
app.add_typer(db_app, name="db")


@app.command()
def version() -> None:
    """Display system version and active cryptographic security parameters."""
    panel_content = (
        f"[bold cyan]Service:[/bold cyan] {settings.APP_NAME}\n"
        f"[bold cyan]Version:[/bold cyan] 0.1.0\n"
        f"[bold cyan]Argon2id Memory Cost:[/bold cyan] {settings.ARGON2_MEMORY_COST} KiB (64 MB)\n"
        f"[bold cyan]Argon2id Time Cost:[/bold cyan] {settings.ARGON2_TIME_COST} passes\n"
        f"[bold cyan]Argon2id Parallelism:[/bold cyan] {settings.ARGON2_PARALLELISM} threads\n"
        f"[bold cyan]Lockout Threshold:[/bold cyan] {settings.MAX_FAILED_LOGIN_ATTEMPTS} attempts\n"
        f"[bold cyan]Lockout Base Delay:[/bold cyan] {settings.LOCKOUT_BASE_DURATION_SECONDS}s\n"
        f"[bold cyan]Max Lockout Delay:[/bold cyan] {settings.MAX_LOCKOUT_DURATION_SECONDS}s\n"
        f"[bold cyan]TOTP Window Tolerance:[/bold cyan] ±{settings.TOTP_WINDOW} (30s steps)"
    )
    console.print(
        Panel(panel_content, title="Security & Cryptographic Parameters", border_style="green")
    )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host address"),
    port: int = typer.Option(8000, "--port", "-p", help="Listen port"),
    reload: bool = typer.Option(False, "--reload", help="Enable live auto-reload"),
) -> None:
    """Launch production-hardened REST API service via Uvicorn."""
    console.print(
        f"[bold green]Starting {settings.APP_NAME} on http://{host}:{port}...[/bold green]"
    )
    uvicorn.run("secure_auth.api.app:app", host=host, port=port, reload=reload)


@db_app.command("init")
def database_init() -> None:
    """Initialize database tables and constraints."""
    engine = get_engine()
    init_db(engine)
    console.print("[bold green]Database schema successfully initialized.[/bold green]")


@user_app.command("create")
def user_create(
    username: str = typer.Option(..., "--username", "-u", prompt=True, help="Username"),
    email: str = typer.Option(..., "--email", "-e", prompt=True, help="Email address"),
    password: str = typer.Option(
        ...,
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Secure account password",
    ),
) -> None:
    """Provision a new user account with Argon2id password hash."""
    engine = get_engine()
    init_db(engine)
    with Session(engine) as session:
        auth_service = AuthService(session)
        try:
            user = auth_service.register(username=username, email=email, password=password)
            session.commit()
            console.print(
                f"[bold green]User '{user.username}' created successfully! "
                f"(UUID: {user.uuid})[/bold green]"
            )
        except UserAlreadyExistsError as err:
            console.print(
                f"[bold red]Error:[/bold red] Username '{username}' or email '{email}' registered."
            )
            raise typer.Exit(code=1) from err
        except ValueError as exc:
            console.print(f"[bold red]Validation Error:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc


@user_app.command("list")
def user_list() -> None:
    """Display registered users and security status in a table."""
    engine = get_engine()
    init_db(engine)
    with Session(engine) as session:
        users = session.exec(select(User).order_by(col(User.id))).all()

        if not users:
            console.print("[yellow]No registered users found.[/yellow]")
            return

        table = Table(title="Registered User Accounts", show_lines=True)
        table.add_column("ID", justify="right", style="cyan")
        table.add_column("Username", style="bold")
        table.add_column("Email", style="blue")
        table.add_column("Active", justify="center")
        table.add_column("2FA Enabled", justify="center")
        table.add_column("Failed Logins", justify="right")
        table.add_column("Lockout Until", style="magenta")

        for u in users:
            active_str = "[green]Yes[/green]" if u.is_active else "[red]No[/red]"
            mfa_str = "[green]Enabled[/green]" if u.mfa_enabled else "[yellow]Disabled[/yellow]"
            locked_str = str(u.locked_until) if u.locked_until else "[dim]None[/dim]"

            table.add_row(
                str(u.id),
                u.username,
                u.email,
                active_str,
                mfa_str,
                str(u.failed_login_attempts),
                locked_str,
            )

        console.print(table)


@user_app.command("unlock")
def user_unlock(
    identifier: str = typer.Argument(..., help="Username or email of user to unlock"),
) -> None:
    """Manually clear account lockout and reset failed login attempts."""
    engine = get_engine()
    init_db(engine)
    with Session(engine) as session:
        user_repo = UserRepository(session)
        user = user_repo.get_by_identifier(identifier)
        if not user:
            console.print(f"[bold red]Error:[/bold red] User '{identifier}' not found.")
            raise typer.Exit(code=1)

        user_repo.reset_failed_attempts(user)
        session.commit()
        console.print(
            f"[bold green]Account '{user.username}' successfully unlocked and reset.[/bold green]"
        )


@audit_app.command("list")
def audit_list(
    limit: int = typer.Option(50, "--limit", "-n", help="Number of recent records to display"),
) -> None:
    """Display immutable security audit logs with status color-coding."""
    engine = get_engine()
    init_db(engine)
    with Session(engine) as session:
        audit_service = AuditService(session)
        events = audit_service.get_recent_events(limit=limit)

        if not events:
            console.print("[yellow]No security audit records logged yet.[/yellow]")
            return

        table = Table(title=f"Security Audit Log Trail (Last {limit} Events)", show_lines=True)
        table.add_column("ID", justify="right", style="cyan")
        table.add_column("Timestamp (UTC)", style="dim")
        table.add_column("Event Type", style="bold")
        table.add_column("User", style="blue")
        table.add_column("Origin IP")
        table.add_column("Status", justify="center")

        for e in events:
            if e.status == "SUCCESS":
                status_formatted = "[bold green]SUCCESS[/bold green]"
            elif e.status == "WARNING":
                status_formatted = "[bold yellow]WARNING[/bold yellow]"
            else:
                status_formatted = "[bold red]FAILURE[/bold red]"

            user_disp = e.username or (str(e.user_id) if e.user_id else "-")

            table.add_row(
                str(e.id),
                str(e.timestamp)[:19],
                e.event_type,
                user_disp,
                e.ip_address or "-",
                status_formatted,
            )

        console.print(table)
