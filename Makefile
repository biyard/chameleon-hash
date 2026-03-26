.PHONY: measure measure-release measure-log clean

measure:
	cargo run

measure-release:
	cargo run --release

measure-log:
	mkdir -p results
	cargo run --release | tee results/measure-release.log

clean:
	cargo clean
