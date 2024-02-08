ldapsearch -x -H ldap://localhost:389

# Check the exit status
if [ $? -eq 0 ]; then
  echo "ldapsearch completed successfully."
else
  echo "ldapsearch encountered an error."
fi
