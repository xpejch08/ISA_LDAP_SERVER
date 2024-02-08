import python_ldap as ldap

# LDAP Server Configuration
ldap_server = 'localhost'
ldap_port = 389
ldap_search_base = 'dc=example,dc=com'  # Change to your LDAP server's search base
ldap_search_filter = '(cn=John Doe)'  # Change to the desired search filter

# Initialize an LDAP connection
ldap_connection = ldap.open(ldap_server, ldap_port)

try:
    # Perform an anonymous bind
    ldap_connection.simple_bind_s('', '')

    # Wait for and receive the Bind Response
    result_type, result_data, result_msg_id, result_controls = ldap_connection.result(ldap_connection.result3(ldap.MSG_BIND, ldap.SCOPE_SUBTREE))

    # Check the result of the Bind Response
    if result_type == ldap.RES_BIND:
        result_code, result_msg = result_data[0]
        if result_code == 0:
            print("Bind successful")
        else:
            print(f"Bind failed: {result_msg}")
    else:
        print("Unexpected response during bind")

    # Perform the LDAP search
    ldap_result_id = ldap_connection.search(ldap_search_base, ldap.SCOPE_SUBTREE, ldap_search_filter)

    # Retrieve search results
    result_set = []
    while True:
        result_type, result_data, result_msg_id, result_controls = ldap_connection.result(ldap_result_id, 0)
        if not result_data:
            break
        if result_type == ldap.RES_SEARCH_ENTRY:
            result_set.append(result_data)

    # Display search results
    for entry in result_set:
        dn, attributes = entry[0]
        print(f"DN: {dn}")
        for attribute, values in attributes.items():
            print(f"{attribute}: {', '.join(values)}")

    # Unbind from the LDAP server
    ldap_connection.unbind()
except ldap.LDAPError as e:
    print(f"LDAP Error: {e}")
