import csv
import json

with open("wg_data_local.json") as file:
  wg_local = json.loads(file.read())

with open("wg_data_nonlocal.json") as file:
  wg_nonlocal = json.loads(file.read())

with open("py_data_local.json") as file:
  py_local = json.loads(file.read())

with open("py_data_nonlocal.json") as file:
  py_nonlocal = json.loads(file.read())

py_local_file = open("py_local_data_1000B.csv", "w", newline="")
py_nonlocal_file = open("py_nonlocal_data_1000B.csv", "w", newline="")
wg_local_file = open("wg_local_data_1000B.csv", "w", newline="")
wg_nonlocal_file = open("wg_nonlocal_data_1000B.csv", "w", newline="")

py_local_csv = csv.DictWriter(py_local_file, ["packets", "runtime"], delimiter=",")
py_nonlocal_csv = csv.DictWriter(py_nonlocal_file, ["packets", "runtime"], delimiter=",")
wg_local_csv = csv.DictWriter(wg_local_file, ["packets", "runtime"], delimiter=",")
wg_nonlocal_csv = csv.DictWriter(wg_nonlocal_file, ["packets", "runtime"], delimiter=",")

py_local_csv.writeheader()
py_nonlocal_csv.writeheader()
wg_local_csv.writeheader()
wg_nonlocal_csv.writeheader()

for x, y in zip(py_local["x"], py_local["ys"]["1000"]):
    py_local_csv.writerow(dict(packets=x, runtime=y))

for x, y in zip(py_nonlocal["x"], py_nonlocal["ys"]["1000"]):
    py_nonlocal_csv.writerow(dict(packets=x, runtime=y))

for x, y in zip(wg_local["x"], wg_local["ys"]["1000"]):
    wg_local_csv.writerow(dict(packets=x, runtime=y))

for x, y in zip(wg_nonlocal["x"], wg_nonlocal["ys"]["1000"]):
    wg_nonlocal_csv.writerow(dict(packets=x, runtime=y))

py_local_file.close()
py_nonlocal_file.close()
wg_local_file.close()
wg_nonlocal_file.close()

