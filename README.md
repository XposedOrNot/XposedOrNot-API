<h1 align="center">XposedOrNot API</h1>
 
<p align="center">
🎉 Your free API for real-time data breach monitoring and analytics. <br>
<a href="https://github.com/XposedOrNot/XposedOrNot-API/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue"></a>
<a href="https://github.com/psf/black"><img src="https://img.shields.io/static/v1?label=code%20style&message=black&color=blue"></a>
<img src="https://img.shields.io/badge/code%20style-pep8-blue.svg">
<a href="https://github.com/XposedOrNot/XposedOrNot-API/blob/master/CONTRIBUTING.md"><img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen"></a>
<a href="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/black.yml"><img src="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/black.yml/badge.svg" alt="Black"></a>
<a href="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/pylint.yml"><img src="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/pylint.yml/badge.svg" alt="Pylint"></a>
 <a href="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/codeql.yml"><img src="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
<a href="https://securityscorecards.dev/viewer/?uri=github.com/XposedOrNot/XposedOrNot-API"><img src="https://api.securityscorecards.dev/projects/github.com/XposedOrNot/XposedOrNot-API/badge" alt="OpenSSF Scorecard"></a>
<a href="https://www.bestpractices.dev/projects/11418"><img src="https://www.bestpractices.dev/projects/11418/badge?v=1" alt="OpenSSF Best Practices"></a>

<p align="center">     
    <a href="https://xposedornot.docs.apiary.io/" target="_blank">XposedOrNot API Playground</a>    ·
    <a href="https://xposedornot.com" target="_blank"> XposedOrNot.com</a>
</p> <br>  
</p>  
<p align="center">
  <img src="https://github.com/XposedOrNot/XposedOrNot-Website/blob/master/static/images/xon.webp" alt="XposedOrNot demo">
</p>


## What is XposedOrNot API?

XposedOrNot is like your personal guard against data breaches. It's a platform that warns you when your email account might be at risk because of a public data breach. Knowing about these breaches can help you reduce the chances of your data getting exposed. Plus, it's totally open-source so you can see exactly how it works.

The XposedOrNot API is the heart of this system. It's what makes the checks for data breaches and sends you the alerts. 

And guess what? It's FREE. 

It gives you all the details about any data breaches that it finds, plus some useful stats about an email.

The API was built and is maintained by Devanand Premkumar.
[![Twitter](https://img.shields.io/badge/Twitter-blue?style=flat-square&logo=twitter&logoColor=white&url=https%3A%2F%2Ftwitter.com%2Fdevaonbreaches)](https://twitter.com/devaonbreaches)
[![Mastodon](https://img.shields.io/badge/-Mastodon-blue?style=flat-square&logo=mastodon&logoColor=white&link=https://infosec.exchange/@DevaOnBreaches)](https://infosec.exchange/@DevaOnBreaches)

## Quick Example

Check if an email has been exposed in data breaches:

```bash
curl https://api.xposedornot.com/v1/check-email/test@example.com
```

Response:
```json
{
  "breaches": [["Adobe"], ["LinkedIn"]],
  "email": "test@example.com"
}
```

Get detailed breach analytics:
```bash
curl "https://api.xposedornot.com/v1/breach-analytics?email=test@example.com"
```

## Rate Limits & API Access

- **No API key required** for basic endpoints (`/v1/check-email`, `/v1/breach-analytics`, `/v1/breaches`)
- **Rate limits**: 2 requests/second, 100 requests/day per IP
- **API key required** for domain breach monitoring (enterprise feature)

For full documentation, see the [API docs](https://XposedOrNot.com/api_doc) and [API playground](https://xposedornot.docs.apiary.io/).

## Why use XposedOrNot API?

XposedOrNot API is the power behind XposedOrNot, and it's the first open-source tool that monitors and alerts you about data breaches.

This API is your go-to for all information related to data breaches that XposedOrNot has collected and keeps up-to-date. Here are some things you can do with it:
- Look up whether an email address has been caught in a data breach and get some stats about it
- See if an email address has been exposed in public pastes
- Do a combined search to check both data breach and pastes exposure for an email address
- Check for exposed passwords without having to reveal who you are

If you'd rather skip the API and check data breach info directly, you can do that on our website at : https://XposedOrNot.com.


## Security

This project is fully open-source and uses automated security tooling (Black, Pylint, CodeQL, OpenSSF Scorecard). For security details, see [SECURITY.md](SECURITY.md).

## Prerequisites

- **Docker** (recommended): Docker 20.10+ and Docker Compose V2
- **Local install**: Python 3.9+, Google Cloud SDK

## Quick Start for Local Development

### Using Docker Compose (Recommended)

1. **Clone the Repository:**

    ```shell
    git clone https://github.com/XposedOrNot/XposedOrNot-API
    ```

2. **Update the necessary environment variables in the docker-compose.yml file if needed, then run:**


    ```shell
    docker compose up
    ```

    This command will build API and Datastore Docker images. Note that the project source directory is mapped in the Docker container, so any changes in the source code won't require rebuilding the Docker image.

### Local Installation

1. **Clone the Repository:**

    ```shell
    git clone https://github.com/XposedOrNot/XposedOrNot-API
    ```

2. **Install Required Packages**

    ```shell
    sudo apt-get install -y google-cloud-sdk google-cloud-sdk-app-engine-python python3-pip build-essential libffi-dev python3-dev 
    ```

3. **Install Python Libraries**


    ```shell
    pip3 install -r requirements.txt
    ```

4. **Setup Google Cloud Datastore**

    Before running XposedOrNot-API, choose one of the following options:

-   [Run local Google DataStore emulator](https://cloud.google.com/datastore/docs/tools/datastore-emulator)
    and debug using the local emulator rather than directly connect to Google DataStore. 

    ```shell
    # For posix platforms, e.g. linux, mac:
    gcloud beta emulators datastore start
    ```

-   [Authenticate to Google DataStore](https://cloud.google.com/sdk/gcloud/reference/beta/auth/application-default) and directly debug using Google DataStore.

5. **Run the application**

    ```shell
    python3 main.py
    ```

## Contributing

Please read [CONTRIBUTING.md](https://github.com/XposedOrNot/XposedOrNot-API/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.


## Authors

* **Devanand Premkumar** - *Initial work* - [XposedOrNot-API](https://github.com/XposedOrNot/XposedOrNot-API)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Security Vulnerability Reporting

Please do not report security vulnerabilities through public GitHub issues. Instead, refer to our [Responsible Disclosure Guidelines](https://xposedornot.com/responsible-disclosure) for reporting these issues in a secure manner.


## Acknowledgments

* Big shout-out to Python and all the people looking after the modules we've used. You guys rock!

* And a round of applause for everyone who's reviewed our code. Your eyes make all the difference.

## Show Your Support

If you find this project useful:

- Star the repository
- Fork it and contribute
- Share it with others

