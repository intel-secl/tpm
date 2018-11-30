echo "Starting TPM 1.2 Server ..."
tpm_server > tpm_server &
sleep 1
echo "Executing BIOS Commands ..."
tpmbios
echo "Creating EK ..."
createek
echo "Defining NV space ..."
nv_definespace -in ffffffff -sz 0
echo "Starting tcsd ..."
tcsd -e
sleep 1
echo "Taking ownership ..."
NIARL_TPM_Module -mode 1 -owner_auth 31323334 -nonce 0000 -debug
echo "Creating AIK ..."
sleep 1
makeidentity -la HIS_Identity_Key -pwdk 1234 -ok aik -pwdo 1234
NIARL_TPM_Module -mode 9 -key_type identity -key_auth 31323334 -key_blob $(xxd -p aik.key | tr -d '\n') -key_index 1 -debug
echo "DONE"
