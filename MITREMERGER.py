#!/usr/bin/env python3
import argparse
import json

def read_file(file_location):
    with open(file_location, "r") as fp:
        output = json.load(fp)
        return output
    return None

def merge_layers(layer_list):
    list_size = len(layer_list)
    score = 1
    output = { "description" : "MITREMERGER merged output",
              "name" : "Merged Layers",
              "domain": "enterprise-attack",
              "versions": {
                  "layer": "4.4",
                  "attack": "16",
                  "navigator": "4.8.1"
                  },
              "techniques" : [],
              "gradient" : {
                  "colors": [
                      "#ffffff",
                      "#66b1ff"
                      ],
                  "minValue": 0,
                  "maxValue": f"{list_size}"
                  },
              "legendItems": [
                  {
                      "label": "Used by attackers",
                      "color": "#66b1ff"
                  }]
              }
    seen_techniques = {}
    for layer in layer_list:
        for technique in layer["techniques"]:
            if not technique["techniqueID"] in seen_techniques.keys():
                technique["score"] = score
                seen_techniques[technique["techniqueID"]] = technique
            else:
                seen_techniques[technique["techniqueID"]]["score"] += score
                if "comment" in technique.keys():
                    if "comment" in seen_techniques[technique["techniqueID"]].keys():
                        seen_techniques[technique["techniqueID"]]["comment"] += technique["comment"]
                    else:
                        seen_techniques[technique["techniqueID"]]["comment"] = technique["comment"]

    for technique in seen_techniques:
        output["techniques"].append(seen_techniques[technique])
    return json.dumps(output)

def main(args):
    layers = []
    output = ""
    
    for file in args.filenames:
        layer = read_file(file)
        if layer:
            layers.append(layer)

    output = merge_layers(layers)

    if args.output:
        with open(args.output, "w") as fp:
            fp.write(output)
    else:
        print(output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            prog="MITREMERGER",
            description="Merges MITRE ATT&CK Navigator layers")
    parser.add_argument('filenames', nargs="*")
    parser.add_argument("-o","--output", nargs="?")
    args = parser.parse_args()
    main(args)
