# Koala Shield 🐨 🛡

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
    <li><a href="#test">Tests</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

Koala Shield is a small package and CLI tool written in Go to help investigate IP address/ASNs and manage block lists in AWS WAF Classic.

Koala Shield makes it easy to track any IP address to their ASN owner and, if the ASN owner appears malicious, quickly create a AWS WAF Classic block rule to guard against widespread malicious behavior.

If a malicious actor is using a less-than scrupulous cloud provider to DDoS your application Koala Shield can be used to temporarily block the cloud provider and give you time to find a more permanent solution.

**Be careful when blocking an entire ASN!** An ASN can encompass a wide range of services and networks so be sure to triple confirm before enabling the block. Koala Shield makes it easy to rollback a block if needed.

<!-- GETTING STARTED -->

## Getting Started

### Prerequisites

Koala Shield requires Go 1.15 or higher. As a prerequisite please [download and install Go](https://golang.org/doc/install) and make sure Go compiled binaries are included in your `$PATH` (e.g. `export PATH=$GOPATH/bin:$PATH`)

### Installation

1. Install the binary
   ```sh
   go get github.com/koala-labs/koala-shield
   ```
2. Set your [AWS credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-config) and make sure to export your desired AWS region.
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

<!-- Tests -->

## Tests

Koala Shield has a full unit-test suite.

Use the following command to run the tests and output function-level code coverage

```sh
go test ./... -coverprofile coverage.out && go tool cover -func coverage.out
```

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Run the test suite (`go test ./...`)
4. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
5. Push to the Branch (`git push origin feature/AmazingFeature`)
6. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache License, Version 2.0. See `LICENSE` for more information.

<!-- CONTACT -->

## Contact

Koala Labs - [@https://twitter.com/koala_labs](https://twitter.com/https://twitter.com/koala_labs) - engineering@koala.io
