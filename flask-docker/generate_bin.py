
with open("ti_buck_fw.bin", 'wb') as f:
    f.write('5'.encode('utf-8') * 16 * 1024)

with open("ti_buck_fw_key.bin", 'wb') as f:
    f.write('a'.encode('utf-8') * 32)
