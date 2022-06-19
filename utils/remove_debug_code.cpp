// extract to string

using namespace std;

#include <iostream>
#include <string>
#include <regex>

int main ()
{
  string name;
  unsigned  ifdef_depth = 0;

  while (!getline(cin, name).eof()) {
	  if (regex_search(name, regex("^[[:space:]]*#[[:space:]]*ifdef[[:space:]]*DEBUG_"))) {
		  cerr << "Start debug\n";
		  ifdef_depth++;
	  } else if (regex_search(name, regex("^[[:space:]]*#[[:space:]]*if[[:space:]]*\\(*[[:space:]]*defined[[:space:]]*DEBUG_"))) {
		  cerr << "Start debug defined\n";
		  ifdef_depth++;
	  } else if (ifdef_depth && regex_search(name, regex("^[[:space:]]*#[[:space:]]*if"))) {
		  ifdef_depth++;
		  cerr << "Increase depth to " << ifdef_depth << "\n";
	  } else if (ifdef_depth && regex_search(name, regex("^[[:space:]]*#[[:space:]]*endif"))) {
		  ifdef_depth--;
		  cerr << "Reducing depth to " << ifdef_depth << "\n";
	  } else if (regex_search(name, regex("^[[:space:]]*(?://)?#[[:space:]]*define[[:space:]]*DEBUG_"))) {
		  // We just ignore these
	  } else if (!ifdef_depth)
		  cout << name << "\n";
  }

  return 0;
}
