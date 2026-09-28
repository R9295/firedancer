# Skips BLS signature checks in votor certificates, for test suites
# whose validators sign with a fake signature.

FD_AG_NO_CERT_VERIFY:=1
CPPFLAGS+=-DFD_AG_NO_CERT_VERIFY=1
