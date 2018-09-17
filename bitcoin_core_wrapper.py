#! /usr/bin/env python3

# A collection of proposed Bitcoin Core RPC commands useful for hardware wallets.
# It expects a (hardware) signer listening on port 8331, which should support
# a JSON RPC similar to the one in hwi_server.py (this needs to be standardized).
#
#
# Install:
# pip3 install json-rpc werkzeug
# compile ... branch of Bitcoin Core
#
# Usage:
# # ../bitcoin/src/bitcoind -daemon
# $ python3 mock_bitcoin_core.py -signrpc=http://localhost:8331
# $ bitcoin-cli -rpcport 8330 getsigners
#    [{device_id: "0000001"}]
# Get list of public keys from device for receive and change addresses:
# $ bitcoin-cli -rpcport 8330 getsignerkeypool 0000001 m/44'/0'/0'/0 0 99 true
# $ bitcoin-cli -rpcport 8330 getsignerkeypool 0000001 m/44'/0'/0'/0 0 99 false
# Generate receive address (works without device):
# $ bitcoin-cli generateaddress
# Send some coins to it, then spend using:
# $ bitcoin-cli -rpcport 8330 sendtoaddress ... {"signer_device_id": "0000001"}

import argparse
import json
import requests
from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple
from jsonrpc import JSONRPCResponseManager, dispatcher

parser = argparse.ArgumentParser(description='Bitcoin Core wrapper')
parser.add_argument('-signrpc', dest='signrpc',metavar='HOST',
                    help='Use external signer JSON-RPC (e.g. http://localhost:8331)')
parser.add_argument('-testnet', dest='testnet', action='store_true',
                      help='Use testnet')

args = parser.parse_args()

if args.signrpc == None:
  print("This mock doesn't do anything without -signrpc\n")
  parser.parse_args(['-h'])
  
signer_rpc_url = args.signrpc
  
print("Using signer RPC at", signer_rpc_url)
  
testnet = args.testnet == True

headers = {'content-type': 'application/json'}

# TODO: check if Bitcoin Core is running

def json_rpc_request(url, method, params):
    res = requests.post(
        url, data=json.dumps({"method": method, "params": params, "jsonrpc": "2.0", "id": 0}), headers=headers
    ).json()
    return res["result"]

@dispatcher.add_method
def rpc_help(*args):
    if not args:
      return  """ == Hardware Wallets ==
enumerate
displayaddress "device_id" "bip32_path" ("address_type")
"""
    else:
      methods = {
      # Fetch help text from signer RPC if it's identical:
      "enumerate": json_rpc_request(signer_rpc_url, "help", ["enumerate"]),
      "displayaddress": json_rpc_request(signer_rpc_url, "help", ["displayaddress"])
      }
      return methods.get(args[0], "Unknown command")

@dispatcher.add_method
def rpc_enumerate():
  return json_rpc_request(signer_rpc_url, "enumerate", [])

@dispatcher.add_method
def rpc_displayaddress(*args):
  return json_rpc_request(signer_rpc_url, "displayaddress", args)

@Request.application
def application(request):
    dispatcher["help"] = rpc_help
    dispatcher["enumerate"] = rpc_enumerate
    dispatcher["displayaddress"] = rpc_displayaddress

    response = JSONRPCResponseManager.handle(
        request.get_data(cache=False, as_text=True), dispatcher)
    return Response(response.json, mimetype='application/json')


if __name__ == '__main__':
    run_simple('localhost', 8330 if not testnet else 18330, application)

# TODO: respond to signerdisplayaddress displayaddress, pass on to RPC if device is connected
#          * connect to HWI RPC when needed, fail if not present
# TODO: parse signer argument in sendtoaddress,
