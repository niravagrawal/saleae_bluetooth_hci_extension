# saleae_bluetooth_hci_extension
This repo maintains Saleae Extension for Capturing Bluetooth HCI Packets from Serial UART Analyzer

Prerequesits:
- UART TX and UART RX IO Lines needs to be tapped out of the board/module which represents bluetooth-uart-hci interface.
- Need "Ellisys Bluetooth Analyzer" tool on or above "5.0.9019.42078" version
- Need Logic-2 tool with verion 2.4.1.4 or above


Steps
A) Once this extension is added to Logic-2 tool, "Bluetooth HCI Inject to Ellisys" Analyzer will be seen in add analyzer menu. Add Analyzer instances for both UART TX and RX, link it with Async Serial analyzer where UART TX and RX channel data flows. 

B) Do not change Port value if it is not changed in Ellisys HCI Inject panel. Both tool shall use same port value. Default port value is 24352

C) Use "Primary" overview for both UART TX and RX instance. If there are more HCI interface to be monitored, use others. Please enable options to see overview panels in ellisys tool from tools->options->Injection API. 

D) Once both HCI Instance added with correct async_serial instance linked to it, click on "Record" in Ellisys tool and start capture in Logic-2 tool. Do any HCI operation, you will be able to see live HCI transactions in Ellisys tool.

E) This extension supports monitoring up to 3 HCI interfaces (which will needs total 6 instances to be added for both UART TX and UART RX). 

F) User can update UDP port if default port is not available. Extension provides port change in range of 24352-24360.

G) Enable/Disable Console HCI Dump while configuring HCI instance.
