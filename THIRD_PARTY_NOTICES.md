# Third-party notices

AntiAlt downloads the X4BNet VPN network ranges into the local ignored cache `data/vpn-ip-ranges.txt` from https://github.com/X4BNet/lists_vpn. The list and associated scripts are provided under the MIT License.

Copyright (c) 2024 X4B (Mathew Heard)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

AntiAlt also downloads provider IP snapshots from [Joe12387/open-source-vpn-ip-lists](https://github.com/Joe12387/open-source-vpn-ip-lists), including ProtonVPN, AirVPN, IVPN, Mullvad, NordVPN, OVPN, Private Internet Access, RiseupVPN, Surfshark, and Windscribe. That project is dedicated to the public domain under CC0 1.0. Its lists are snapshots and do not distinguish ProtonVPN free from paid server IPs.

AntiAlt downloads ProtonVPN IPv4 ranges from [tn3w/ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs), which states that it refreshes its data daily using Proton API and public routing data. The range file expands advertised server IPs to `/24` networks, so nearby non-VPN addresses may match. The source repository does not state an explicit license; AntiAlt consumes the live public data and does not redistribute a copy in this repository.
