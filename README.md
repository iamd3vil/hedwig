# smtp-server

A high-performance, minimalist SMTP server implemented in Rust.

## Overview

This SMTP server is designed with a focus on speed and simplicity. It provides a streamlined solution for receiving, queuing, and forwarding emails to destination SMTP servers.

## Key Features

- **Fast and Efficient**: Optimized for high-speed email processing.
- **Minimalist Design**: Focuses on core SMTP functionality without unnecessary complexities.
- **Persistent Queue**: Emails are queued on the filesystem, ensuring durability across server restarts.
- **Forward-Only**: Specializes in receiving and forwarding emails, not full SMTP functionality.
- **Functionality**: Will support DKIM, SPF, DMARC, and other email security features.

## Use Cases

Ideal for scenarios where you need:
- You want to send emails fast from your application and don't care about all the features of a full SMTP server.

## Limitations

- Not intended for full SMTP server functionality
- Does not include advanced features like email filtering, MTA, or MDA functionality.

## Getting Started

[Include basic instructions on how to install, configure, and run the server]

## Configuration

[Briefly explain any configuration options or files]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Specify the license under which this project is released]

## Support

[Provide information on how to get support or report issues]
