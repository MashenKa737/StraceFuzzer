BEGIN {
	flagWasStart = 0
	separatingRegex = "^[\ \t\-]*[\-]+[\ \t\-]*$"
	C_identifierRegex = "^[_a-zA-Z][_a-zA-Z0-9]*$"
	numbersRegex = "^[0-9]+$"
	percentRegex = "^(100\.00)|([0-9]{1,2}\.[0-9]{2})$"
	secondsRegex = "^[0-9]+\.[0-9]{6}$"
	true = 1
	false = 0
}
{
	if (flagWasStart == 0 && $0 ~ separatingRegex) {
		flagWasStart = 1
	} else if (flagWasStart == 0) {
		next
	} else if (flagWasStart == 1 && $0 ~ separatingRegex) {
		flagWasStart = 0
	} else if (flagWasStart == 1 && testCorrectStraceOutput()) {
		printf "%-20s %-10s\n", $NF, $4
	} else {
		print "awk: Wrong strace output format. Be careful if output of traced process "\
			"is similar to strace output itself. If strace output is actually correct,"\
			"contact the developers. Execution is terminated."
		exit
	}
}
function testCorrectStraceOutput() {
	if (NF < 5 || NF > 6) {
		return $false
	}
	if ($1 !~ percentRegex) {
		return $false
	}
	if ($2 !~ secondRegex) {
		return $false
	}
	if ($3 !~ numbersRegex) {
		return $false
	}
	if ($4 !~ numbersRegex) {
		return $false
	}
	if (NF == 6 && ($5 !~ numbersRegex || $6 !~ C_identifierRegex)) {
		return $false
	}
	if (NF == 5 && $5 !~ C_identifierRegex) {
		return $false
	}
	return $true
}
