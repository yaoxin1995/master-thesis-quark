MAKEFLAGS += -j8

all:: release debug

release:: qvisor_release qkernel_release

qvisor_release:
	make -C ./qvisor release
	
qkernel_release:
	make -C ./qkernel release

debug:: qvisor_debug qkernel_debug

qvisor_debug:
	make -C ./qvisor debug

qkernel_debug:
	make -C ./qkernel debug

clean:
	rm -rf target build

docker:
	sudo systemctl restart docker

install:
	sudo cp -f ./build/qkernel.bin /usr/local/bin/
	sudo cp -f ./build/qkernel_d.bin /usr/local/bin/
	sudo cp -f ./target/release/quark /usr/local/bin/quark
	sudo cp -f ./target/release/quark /usr/local/bin/containerd-shim-quark-v1
	sudo cp -f ./target/debug/quark /usr/local/bin/quark_d
	sudo cp -f ./target/debug/quark /usr/local/bin/containerd-shim-quarkd-v1
	sudo cp -f ./vdso/vdso.so /usr/local/bin/vdso.so
	sudo mkdir -p /etc/quark/
	sudo cp -f ./config.json /etc/quark/
	sudo cp -f ./policy.json /etc/quark/
	sudo cp -f ./sev_snp_guest_attestation_report.bin /etc/quark/      

