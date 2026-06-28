.DEFAULT_GOAL := help

clean-up-cache:
	@echo "Cleaning up Python cache..."
	find . -type d \( -name ".pytest_cache" -o -name "__pycache__" \) -exec rm -rvf {} +

help:
	@echo "Makefile commands:"
	@echo -e "\t make clean-up-cache\t\t- Clean up Python cache files"