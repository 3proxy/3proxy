/* Create list user for 3proxy ACL from LDAP server 
 (c) Kirill Lopuchov lopuchov@mail.ru
*/
#include <stdio.h>
#include <ldap.h>

/*Create list user for 3proxy ACL from LDAP server*/

/* argv[1] = server
   argv[2] = basedn
   argv[3] = user_attribute   
   argv[4] = filter  
   argv[5] = user    
   argv[6] = password 
*/

main(int argc, char *argv[])

{
 LDAP		*ld = NULL;
 LDAPMessage	*res = NULL;
 LDAPMessage	*msg = NULL;
 BerElement 	*ber;
 char   	*getattr,**vals;


 char	*attrs[] = { NULL, NULL };
 int  	i, rc = -1;
 int    lderrno;
 unsigned char tmpbuf[1000];

 if ( argc < 6 )
  {
   printf ("Create 3proxy ACL userlist from ldap server.\ngetldapuser < ldapserver sbasedn user_attribute filter user password > \n");
   printf ("Example: getldapuser 192.168.0.1 dc=domain,dc=com cn (memberOf=cn=internet,cn=Users,dc=domain,dc=com) cn=admin,cn=users,dc=domain,dc=com password  \n");
  }
 
 else
  {
    attrs[0]=strdup(argv[3]);

    /* init ldap ------------------------ */
    ld = ldap_init( argv[1] , 389 );

    if ( ld == NULL ) 
     {
      /*perror( "ldap_init" );*/
      printf("Error init ldap") ;
      exit(1);
     }

    

    /* connect ------------------------ */
   
    rc = ldap_bind_s( ld, argv[5], argv[6], LDAP_AUTH_SIMPLE );

    if ( rc != LDAP_SUCCESS ) 
     {
      ldap_perror( ld, "Error ldap_bind" );
     }



    /* search  ------------------------ */
                  
    rc = ldap_search_s( ld,argv[2], LDAP_SCOPE_SUBTREE,
 				argv[4], attrs, 0, &res );

    /* get val ------------------------*/
    rc=ldap_count_entries(ld,res);

    if (rc > 0)
     {

      msg=ldap_first_entry(ld, res);
      getattr=ldap_first_attribute(ld, msg, &ber);
      while (rc > 0)
       {
        vals=ldap_get_values(ld, msg, getattr);
        if (vals != NULL && vals[0] != NULL )
         {
          i=ldap_count_values(vals);
	  while(i>0)
	   { 
            printf("%s",vals[0]);
            i--; 
       	    if (rc > 1) { printf(",",vals[0]); } 
           }
          ldap_value_free(vals);
         }

        msg=ldap_next_entry(ld, msg);
        rc--;
       } 

     } //end if (rc>0)	
    
   ldap_memfree(res);

  ldap_unbind(ld);

 }/*end else*/

}
