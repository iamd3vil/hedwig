import smtplib
import argparse
from email.message import EmailMessage
import mimetypes
import os


def send_email(
    smtp_server,
    port,
    use_tls,
    use_ssl,
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
        # Create the email message
        msg = EmailMessage()
        msg["From"] = sender_email
        msg["To"] = recipient_emails  # Can be a list or comma-separated string
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
        if use_ssl:
            server_class = smtplib.SMTP_SSL
        else:
            server_class = smtplib.SMTP

        # Send the email with timeout
        with server_class(smtp_server, port, timeout=timeout) as server:
            if not use_ssl and use_tls:
                server.starttls()
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
        description="Send an email with attachments, supporting SSL/TLS and STARTTLS."
    )
    parser.add_argument("--smtp-server", required=True, help="SMTP server address")
    parser.add_argument(
        "--port", type=int, default=587, help="SMTP server port (default: 587)"
    )
    parser.add_argument(
        "--use-tls", type=bool, default=True, help="Use STARTTLS (default: True)"
    )
    parser.add_argument(
        "--use-ssl", type=bool, default=False, help="Use SSL (default: False)"
    )
    parser.add_argument("--smtp-username", required=True, help="SMTP server username")
    parser.add_argument("--smtp-password", required=True, help="SMTP server password")
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

    # Split recipients into a list
    recipients = [email.strip() for email in args.recipient.split(",")]

    send_email(
        smtp_server=args.smtp_server,
        port=args.port,
        use_tls=args.use_tls,
        use_ssl=args.use_ssl,
        smtp_username=args.smtp_username,
        smtp_password=args.smtp_password,
        sender_email=args.sender,
        recipient_emails=recipients,
        subject=args.subject,
        body=args.body,
        attachments=args.attachments,
        timeout=args.timeout,
    )
