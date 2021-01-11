# Koala Shield

<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

Koala Shield is a small package and CLI tool written in Go to help investigate IP address/ASNs and manage block lists in AWS WAF Classic.

Through Koala Shield is easy to track an IP address to their ASN owner and, if the ASN owner appears malicious, quickly create a AWS WAF Classic block rule to guard against any widespread malicious behavior.

<!-- GETTING STARTED -->

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

Koala Shield requires Go 1.15 or higher. As a prerequisite please [download and install Go](https://golang.org/doc/install) in your system

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/koala-labs/koala-shield.git
   ```
2. Set AWS credentials
   ```sh
   export $AWS_REGION=region
   ```

<!-- USAGE EXAMPLES -->

## Usage

Koala Shield has 4 core commands: `lookup`, `block`, `un-block`, and `ipsets`:

### `lookup`

Lookup information about IP addresses and/or ASN numbers (powered by [BPGView](https://bgpview.io/))

Example:

```sh
koala-shield lookup 20473
koala-shield lookup 8.6.8.0
```

### `block`

Block all the prefixes owned by the specified ASN using an AWS WAF Classic IP list.

Example:

```sh
koala-shield block 20473
```

### `un-block`

Un-block an ASN by removing their IP Set from the AWS WAF Classic IP Rules.

Example:

```sh
koala-shield un-block 20473
```

### `ipsets`

List all IP sets registered in AWS WAF Classic.

Example:

```sh
koala-shield ipsets
```

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache License, Version 2.0. See `LICENSE` for more information.

<!-- CONTACT -->

## Contact

Koala Labs - [@https://twitter.com/koala_labs](https://twitter.com/https://twitter.com/koala_labs) - engineering@koala.io
