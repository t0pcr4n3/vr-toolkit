build:
	gcc -g -fno-stack-protector -z execstack templates/vuln_sim_template.c -o vuln_sim

scan:
	python3 scanners/vuln_pattern_sweeper.py --target .

test:
	./vuln_sim
