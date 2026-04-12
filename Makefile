.PHONY: build test clean help

help:
	@echo "jerboa-ethereal - Packet dissection system"
	@echo ""
	@echo "Targets:"
	@echo "  make build         - Compile all Jerboa modules"
	@echo "  make test          - Run test suite"
	@echo "  make check         - Run static checks (verify, lint, security)"
	@echo "  make clean         - Remove compiled artifacts"
	@echo "  make help          - Show this help"

build:
	scheme --libdirs lib --script build.ss

test:
	scheme --libdirs lib --script test-runner.ss

check:
	@echo "Checking dissector DSL..."
	scheme --libdirs lib --script check.ss

clean:
	find lib -name "*.so" -delete
	find lib -name "*.wpo" -delete
	find . -name "*~" -delete

.DEFAULT_GOAL := help
