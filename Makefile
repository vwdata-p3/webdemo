.DEFAULT_GOAL := all

.PHONY: all
all: pep3

.PHONY: pep3
pep3: pep3_pb2.py ristretto_is_build

pep3_pb2.py pep3_pb2_grpc.py: pep3.proto
	python3 -m grpc_tools.protoc \
		--python_out=. \
		--grpc_python_out=. \
		--proto_path=. \
		pep3.proto

config.json secrets.json: pep3
	python3 pep3.py create local_config

ristretto_is_build: ristretto.c ristretto.h
	python3 build_ristretto.py
	rm _ristretto.c
	rm _ristretto.o
	touch ristretto_is_build

# Targets to create profile graphs for the benchmarks in benchmarks.py
benchmark_%.profile: pep3
	python3 pep3.py --dump-stats $@ benchmark --run-servers $* 

benchmark_%.dot: benchmark_%.profile
	gprof2dot -f pstats $< -o $@

benchmark_%.png: benchmark_%.dot
	dot -Tpng $< -o $@

venv: python-requirements.txt
	python3 -m venv venv
	( \
	    . venv/bin/activate ;\
	    pip install -r python-requirements.txt ;\
	)
	
.PHONY: clean
clean:
	-rm pep3_pb2.py pep3_pb2_grpc.py
	-rm benchmark_*.dot
	-rm benchmark_*.profile
	-rm benchmark_*.png
	-rm _ristretto*
	-rm ristretto_is_build
	-rm -r venv
