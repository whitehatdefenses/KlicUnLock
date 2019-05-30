
<!-- PROJECT SHIELDS -->
[![Build Status][build-shield]]()
[![Contributors][contributors-shield]]()
[![MIT License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/whitehatdefenses/KlicUnLock">
    <img src="logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">KlicUnLock</h3>

  <p align="center">
    A Python program to unlock any Tzumi Klic smart padlock!
    <br />
    <br />
    ·
    <a href="https://github.com/whitehatdefenses/KlicUnLock/issues">Report Bug</a>
    ·
    <a href="https://github.com/whitehatdefenses/KlicUnLock/issues">Request Feature</a>
  </p>
</p>



<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]]

This program was developed during scientific research in Bluetooth lock security.  Attempts were made to contact the manufacturer 45 days before release.  This vulnerability was assigned to CVE-2019-11334.

### Built With
Major frameworks used in the project. 
* [Python](https://www.python.org/)
* [bluepy](https://github.com/IanHarvey/bluepy)
* [pycrypto](https://pypi.org/project/pycrypto/)



<!-- GETTING STARTED -->
## Getting Started

You will need a valid account name and password for the Klic Lock application downloadable from [Google Play](https://play.google.com/store/apps/details?id=com.nokelock.klic&hl=en_US) or the [App Store](https://itunes.apple.com/us/app/klic-lock/id1385022356?mt=8).

### Prerequisites

The program requires a Linux operating system with [bluepy](https://github.com/IanHarvey/bluepy) and [pycrypto](https://pypi.org/project/pycrypto/) installed.  See respective links for installation procedures. 


<!-- USAGE EXAMPLES -->
## Usage

Unlock lock associated with valid account and password:
```sh
python KlicUnlock.py -a myaccount@example.com -p mypassword
```

Scan and unlock all locks within range using valid account and password:
```sh
python KlicUnlock.py -a myaccount@example.com -p mypassword -u
```

Unlock lock using lock key and MAC:
```sh
python KlicUnlock.py -k 99999999999999999999999999999999 -m 01:02:03:04:05:06
```



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

Kerry Enfinger - k.enfinger@whitehatdefenses.com

Project Link: [https://github.com/whitehatdefenses/KlicUnLock](https://github.com/whitehatdefenses/KlicUnLock)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Damien Cauquil](https://digital.security)
* [Slawomir Jasek](https://smartlockpicking.com)




<!-- MARKDOWN LINKS & IMAGES -->
[build-shield]: https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square
[contributors-shield]: https://img.shields.io/badge/contributors-1-orange.svg?style=flat-square
[license-shield]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square
[license-url]: https://choosealicense.com/licenses/mit
[product-screenshot]: https://raw.githubusercontent.com/whitehatdefenses/KlicUnLock/master/screenshot.png
