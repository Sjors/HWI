#! /usr/bin/env python3

# JSON-RPC server for hardware wallet interaction.

# Install: 
# pip3 install json-rpc werkzeug

# Usage
# 1. start the server: ./hwi_server.py
# 2. insert hardware wallet
# 3. in another terminal, run ./bitcoin_core_wrapper.py (see usage instructions there)

# Debug
# You can use bitcoin-cli to directly with this server, e.g.: bitcoin-cli -rpcport=8331 help

import argparse
import socket
from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple
from jsonrpc import JSONRPCResponseManager, dispatcher

from hwilib.commands import enumerate, find_device, displayaddress



parser = argparse.ArgumentParser(description='HWI Daemon')
parser.add_argument('-signrpcport', dest='signrpcport', type=int,metavar='PORT',
                    help='Listen for external signer JSON-RPC connections on <PORT> (default: 8331, testnet: 18331)')
parser.add_argument('-testnet', dest='testnet', action='store_true',
                      help='Use testnet')

args = parser.parse_args()

testnet = args.testnet == True

if args.signrpcport == None:
  args.signrpcport = 8331 if not testnet else 18331

@dispatcher.add_method
def rpc_help(*args):
    if not args:
      return  """ == Hardware Wallets ==
enumerate
displayaddress "device_id" "bip32_path" ("address_type")
"""
    else:
      methods = {
      "enumerate": """enumerate

List all available devices

Result:
[                                             (json array of device info)
  {
    "device_id": "00000001",                  (same as master key fingerprint)
    "master_key_fingerprint": "00000001"
    "name": "Ledger"
  }
]
""",
      "displayaddress": """displayaddress "device_id" "bip32_path" ("address_type")

Displays the address specified by a bip32 path on the device.

Arguments:
1. "device_id":   (string, required): value returned by enumerate
2. "bip32_path":  (string, required): e.g. "m/84'/1'/0'/0/0"
3. address_type:  (string, optional): "legacy" (default), "p2sh_segwit" or "bech32"

Result: (none)
"""
      }
      return methods.get(args[0], "Unknown command")

@dispatcher.add_method
def rpc_enumerate():
  res = enumerate()
  return list(map(lambda device: {
    "device_id": device["fingerprint"],
    "master_key_fingerprint": device["fingerprint"],
    "name": device["type"].title()
  }, res))

@dispatcher.add_method
def rpc_displayaddress(*args):
  if len(args) < 2:
    return {'error':'Missing arguments','code':1}

  client = find_device(args[0])
  if not client:
      return {'error':'Could not find device with specified fingerprint','code':1}
  client.is_testnet = testnet

  path = args[1]

  if len(args) == 2:
    client.display_address(path, False, False)
  elif args[2] == "p2sh_segwit":
    client.display_address(path, True, False)
  elif args[2] == "bech32":
    client.display_address(path, False, True)
  else:
    return {'error':'Unknown address type','code':1}

  return ""

@Request.application
def application(request):
    dispatcher["help"] = rpc_help
    dispatcher["enumerate"] = rpc_enumerate
    dispatcher["displayaddress"] = rpc_displayaddress

    response = JSONRPCResponseManager.handle(
        request.get_data(cache=False, as_text=True), dispatcher)
    return Response(response.json, mimetype='application/json')


if __name__ == '__main__':
    run_simple('localhost', args.signrpcport, application)

# TODO: listen for displayaddress command, run displayaddress, return when done
# TODO: etc
