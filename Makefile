build:
	go build -o gopass-ssh-add-tool
# PROG=gopass-ssh-add-tool
# source ./autocomplete/zsh_autocomplete


gen-readme: build
	./gopass-ssh-add-tool gen-readme
