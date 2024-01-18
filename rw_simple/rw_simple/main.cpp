#include <iostream>
#include <fstream>

int main(int argc, char** argv)
{
	std::fstream f(argv[1]);

	if (argc == 3 && argv[2][0] == 'r') {
		if (f.is_open()) {
			std::cout << f.rdbuf();
			std::cout << std::endl;
		}
		else {
			std::cout << "Can't open file" << std::endl;
		}
	}
	else if (argc == 4 && argv[2][0] == 'w') {
		if (f.is_open()) {
			f << argv[3];
		}
		else {
			std::cout << "Can't open file" << std::endl;
		}
	}
	else {
		std::cout << "Unknown flag. 'r' - read, 'w' - write supported only";
		std::cout << std::endl;
		exit(1);
	}

	f.close();
	return 0;
}