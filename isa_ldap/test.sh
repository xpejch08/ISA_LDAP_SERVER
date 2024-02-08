#!/bin/bash

# Function to run ldapsearch and compare results
run_test() {
    query="$1"
    expected_file="$2"

    # Run ldapsearch and save output to a temp file
    ldapsearch -x -H ldap://localhost -x "$query" > temp_output.ldif

    # Compare actual output to expected output
    if diff -q temp_output.ldif "$expected_file" > /dev/null; then
        echo "Test Passed for query: $query"
    else
        echo "Test Failed for query: $query"
        echo "Diff:"
        diff temp_output.ldif "$expected_file"
    fi

    # Cleanup
    rm temp_output.ldif
}

# Run tests
run_test "(cn=Pejchar*)" "expectedOut/expected1.ldif"
run_test "(uid=xpejch08)" "expectedOut/expected2.ldif"
run_test "(&(cn=*stepan)(cn=p*))" "expectedOut/expected3.ldif"
run_test "(&(!(mail=*a*))(mail=*en*))" "expectedOut/expected4.ldif"
run_test "userid=aaaaaaaa08" "expectedOut/expected5.ldif"
run_test "(|(cn=*stepan)(cn=p*))" "expectedOut/expected6.ldif"
run_test "(&(&(cn=*stepan)(uid=xp*))(mail=*p*))" "expectedOut/expected7.ldif"


# Add more run_test calls for different queries and expected files

