SAGEFILES := $(basename $(notdir $(wildcard *.sage)))
PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

setup:
	cp voprf/poc/h2c/poc/hash_to_field.py .
	cp voprf/poc/h2c/poc/*.sage .
	cp voprf/poc/*.sage .

test: pyfiles
	@mkdir -p vectors
	sage test_opaque_ake.sage

vectors: pyfiles
	@mkdir -p vectors
	sage test_opaque_ake.sage
	python3 format_test_vectors.py vectors/vectors.json > vectors/formatted.txt

.PHONY: clean
clean:
	rm -rf sagelib *.pyc *.sage.py *.log __pycache__

.PHONY: distclean
distclean: clean
	rm -rf vectors ascii
