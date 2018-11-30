tpm2_server -rm > tpm2_server.log &
sleep 1
# Tpm Initialization
echo "Initializing TPM Simulator ..."
tpm2_startup --clear -V
echo "Taking ownership ..."
tpm2_changeauth -o ${ownerAuth:-hex:31323334} -e ${endorseAuth:-hex:31323334} -l ${lockoutAuth:-hex:31323334}
echo "Creating SRK ..."
tpm2_createprimary -a o -P hex:31323334 -g sha256 -G rsa -o spk.context
tpm2_evictcontrol -a o -P ${ownerAuth:-hex:31323334} -c spk.context -p 0x81000000

echo "Flushing Context ..."
tpm2_flushcontext -t

# create ek
echo "Creating EK ..."
tpm2_createek -e hex:31323334 -o hex:31323334 -G rsa -p ek.key -c 0x81000001
echo "Flushing Context ..."
tpm2_flushcontext -t
# Create AIK
echo "Creating AIK ..."
tpm2_createak -o hex:31323334 -e hex:31323334 -P hex:31323334 -C 0x81000001 -k 0x81018000 -G 0x1 -D 0xb -s 0x14 -P hex:31323334 -p aik.pub -r aik.priv -n aik.name

echo "DONE"
