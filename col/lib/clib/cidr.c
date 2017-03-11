/*! \file cidr.c
* @author ritesh pradhan
* @date 8/22/2013
    
    Check the given device_ip against the config ips (cidr address inclusive) and returns the ip that is in config.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* External Libaries */ 
#include <libcidr.h>
#include <jansson.h>

/* Custom made */
#include "cidr.h"

/**
  A number to represent FALSE in this code
 */
#define FALSE				0
/**
  A number to represent TRUE in this code
 */
#define TRUE				1

/**
*	@brief 	Check if dev_ip_cidr is contained in config_ip_cidr
*	@param[in] dev_ip device ip
*	@param[in] config_ip config ip(dev ip or dev ip of certain range)
*	@return ip
*/
static char *contained_in(char *dev_ip, const char *config_ip) {
	
 	CIDR *dev_ip_cidr, *config_ip_cidr;
 	char *str_dev_ip_cidr, *str_config_ip_cidr;

 	int cflags;
	cflags=CIDR_NOFLAGS;


	if(dev_ip==NULL || strlen(dev_ip)==0 || config_ip==NULL || strlen(config_ip)==0) {
		// lplog("Error: Can't get cidr-block's from your input!\n");
		return NULL;
	}

	/* Parse 'em both */
	dev_ip_cidr = cidr_from_str(dev_ip);
	config_ip_cidr = cidr_from_str(config_ip);

	if(dev_ip_cidr==NULL || config_ip_cidr==NULL) {
		// lplog("Error: Can't parse cidr-blocks: '%s' and '%s'\n",dev_ip,  config_ip);
		return NULL;
	}

	str_dev_ip_cidr = cidr_to_str(dev_ip_cidr, cflags);
	str_config_ip_cidr = cidr_to_str(config_ip_cidr, cflags);

	/*
	 * OK, now we've got 'em.  Start some comparisons.
	 * Note that none of the following is an _error_; they're all
	 * answers.
	 */
//#define PROTOSTR(x) (((x)->proto==CIDR_IPV4)?"IPv4":"IPv6")

	/* Are they even the same address family? */
	if(dev_ip_cidr->proto != config_ip_cidr->proto)
	{
		// lplog("Blocks are different address families:\n"
		//        "  - '%s' is %s\n"
		//        "  - '%s' is %s\n",
		//        str_dev_ip_cidr, PROTOSTR(dev_ip_cidr),
		//        str_config_ip_cidr, PROTOSTR(config_ip_cidr));
		
		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return NULL;
	}

	/* dev_ip_cidr inside config_ip_cidr? */
	if(cidr_contains(config_ip_cidr, dev_ip_cidr)==0)
	{
		// lplog("%s block '%s' is wholly contained within '%s'\n",
		// 		PROTOSTR(dev_ip_cidr), str_dev_ip_cidr, str_config_ip_cidr);

		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return strdup(config_ip);
	}

	/* config_ip_cidr inside dev_ip_cidr? */
	if(cidr_contains(dev_ip_cidr, config_ip_cidr)==0)
	{
		// lplog("%s block '%s' is wholly contained within '%s'\n",
		// 		PROTOSTR(dev_ip_cidr), str_config_ip_cidr, str_dev_ip_cidr);

		free(str_dev_ip_cidr); 
		free(str_config_ip_cidr);
		cidr_free(dev_ip_cidr);
		cidr_free(config_ip_cidr);
		
		return strdup(config_ip);
	}

	/* Otherwise, they're totally unrelated */
	// lplog("%s blocks '%s' and '%s' don't intersect.\n",
	// 		PROTOSTR(dev_ip_cidr), str_config_ip_cidr, str_dev_ip_cidr);
	return NULL;
	/* NOTREACHED */

}


/**
*	@brief 	Check and return dev_ip (device ip) or CIDR address (containing dev_ip) if present in the config
*	@param[in]  dev_ip device ip
*	@param[in]  client_map contain the dev_ip of difffernt devices
*	@return ip or NULL
*/
char* get_config_ip(char *dev_ip, json_t *client_map) {
	const char *config_ip;

	/*	Check if dev_ip already present in the config */
	json_t *dev_config = json_object_get(client_map,dev_ip);
	if(dev_config!=NULL)
		return dev_ip;

	/* if dev_ip not present in config, check for the corresponding cidr addresses */

	void *iter_cidr = json_object_iter(client_map);
	while(iter_cidr) {
	    config_ip = json_object_iter_key(iter_cidr);
	    if(contained_in(dev_ip, config_ip)) {
	    	return (char *)config_ip;
	    }
	    /* next iter_cidr */
	    iter_cidr = json_object_iter_next(client_map, iter_cidr);
	}
	return NULL;
}
