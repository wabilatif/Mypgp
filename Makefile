##
## EPITECH PROJECT, 2026
## Makefile
## File description:
## Makefile for my_pgp project and Rust extension
##

NAME		=	my_pgp
LIB_NAME	=	my_rust_module.so
RUST_TARGET	=	target/release/libmy_rust_module.so

all: $(NAME)

$(NAME):
	@chmod +x $(NAME)

bonus:
	@PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 cargo build --release \
		2>/dev/null && cp $(RUST_TARGET) $(LIB_NAME) || true

clean:
	@cargo clean 2>/dev/null || rm -rf target
	@rm -rf __pycache__ src/__pycache__
	@rm -rf src/Asymmetric/__pycache__
	@rm -rf src/Asymmetric/RSA/__pycache__
	@rm -rf src/Hybrid/__pycache__
	@rm -rf src/Symmetric/__pycache__
	@rm -rf src/Symmetric/AES/__pycache__
	@rm -rf src/Symmetric/XOR/__pycache__
	@rm -f $(LIB_NAME)

fclean: clean

re: fclean all

.PHONY: all clean fclean re
