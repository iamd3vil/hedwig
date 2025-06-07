import smtplib
import argparse
from email.message import EmailMessage
import mimetypes
import os


def send_email(
    smtp_server,
    port,
    use_explicit_tls,
    use_starttls,
    smtp_username,
    smtp_password,
    sender_email,
    recipient_emails,
    subject,
    body,
    attachments,
    timeout,
):
    try:
        if use_starttls:
            print("Starting TLS upgrade", use_explicit_tls)
        # elif use_explicit_tls:
        #     print("Starting TLS upgrade")
        # Create the email message
        msg = EmailMessage()
        msg["From"] = sender_email
        msg["To"] = recipient_emails
        msg["Subject"] = subject
        msg.set_content(body)

        # Attach files with proper MIME types and filenames
        for file_path in attachments:
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                    file_name = os.path.basename(file_path)

                # Guess MIME type
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type is None:
                    mime_type = "application/octet-stream"
                maintype, subtype = mime_type.split("/", 1)

                msg.add_attachment(
                    file_data,
                    maintype=maintype,
                    subtype=subtype,
                    filename=file_name,
                )
            except Exception as e:
                print(f"Error attaching file {file_path}: {e}")

        # Configure SMTP server connection
        if use_explicit_tls:
            server_class = smtplib.SMTP_SSL
        else:
            server_class = smtplib.SMTP

        print(smtp_server, port, timeout)
        # Send the email with timeout
        with server_class(smtp_server, port, timeout=timeout) as server:
            if use_starttls and not use_explicit_tls:
                print("Starting TLS upgrade")
                server.starttls()
            if smtp_username and smtp_password:
                server.login(smtp_username, smtp_password)
            server.send_message(msg)

        print("Email sent successfully!")

    except smtplib.SMTPAuthenticationError as e:
        print(f"Authentication failed: {e}")
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")
    except Exception as e:
        print(f"Failed to send email: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Send an email with attachments, supporting explicit TLS, STARTTLS, or plain text SMTP."
    )
    parser.add_argument("--smtp-server", required=True, help="SMTP server address")
    parser.add_argument(
        "--port",
        type=int,
        default=587,
        help="SMTP server port (default: 587 for STARTTLS/plain, 465 for explicit TLS)",
    )
    parser.add_argument(
        "--use-explicit-tls",
        action="store_true",
        help="Use explicit TLS (connects on SSL/TLS port, e.g., 465)",
    )
    parser.add_argument(
        "--use-starttls",
        action="store_true",
        help="Use STARTTLS (connects on plain port then upgrades, e.g., 587)",
    )
    parser.add_argument(
        "--smtp-username", help="SMTP server username (optional for plain text)"
    )
    parser.add_argument(
        "--smtp-password", help="SMTP server password (optional for plain text)"
    )
    parser.add_argument("--sender", required=True, help="Sender's email address")
    parser.add_argument(
        "--recipient", required=True, help="Recipient email addresses (comma-separated)"
    )
    parser.add_argument("--subject", required=True, help="Email subject")
    parser.add_argument("--body", required=True, help="Email body text")
    parser.add_argument(
        "--attachments", nargs="*", default=[], help="Paths to files to attach"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )

    args = parser.parse_args()

    # Ensure mutually exclusive TLS options
    if args.use_explicit_tls and args.use_starttls:
        raise ValueError(
            "Cannot use both --use-explicit-tls and --use-starttls simultaneously."
        )

    # Adjust default port if explicit TLS is used and port is not explicitly set
    if args.use_explicit_tls and args.port == 587:  # Default port for STARTTLS
        print("Explicit TLS typically uses port 465. Adjusting port to 465.")
        args.port = 465
    elif args.use_starttls and args.port == 465:  # Default port for explicit TLS
        print("STARTTLS typically uses port 587. Adjusting port to 587.")
        args.port = 587

    # Split recipients into a list
    recipients = [email.strip() for email in args.recipient.split(",")]

    send_email(
        smtp_server=args.smtp_server,
        port=args.port,
        use_explicit_tls=args.use_explicit_tls,
        use_starttls=args.use_starttls,
        smtp_username=args.smtp_username,
        smtp_password=args.smtp_password,
        sender_email=args.sender,
        recipient_emails=recipients,
        subject=args.subject,
        body=args.body,
        attachments=args.attachments,
        timeout=args.timeout,
    )
