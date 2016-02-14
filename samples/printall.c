/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "nids.h"


#include <libxml/parser.h>
#include <libxml/xpath.h>


//解析内存中xml格式的字符串,buffer必须以null结尾才能解析
xmlDocPtr 
get_doc_from_memory(char *buffer, int size){
	
	if(NULL == buffer || size == 0)
		return NULL;	
	xmlDocPtr doc;
	doc = xmlParseMemory(buffer, size);
	if (doc == NULL ) {
		//fprintf(stderr,"Document not parsed successfully. \n");
		return NULL;
	}
	return doc;
}

//解析xml文件
xmlDocPtr 
get_doc_from_file (char *docname){

	if(NULL == docname)
		return NULL;
	xmlDocPtr doc;
	doc = xmlParseFile(docname);
	
	if (doc == NULL ) {
		//fprintf(stderr,"Document not parsed successfully. \n");
		return NULL;
	}
	return doc;
}

//get node set by xpath
xmlXPathObjectPtr 
get_node_set (xmlDocPtr doc, xmlChar *xpath){


	if(NULL == doc || NULL == xpath)
		return NULL;
	xmlXPathContextPtr context;
	xmlXPathObjectPtr result;

	context = xmlXPathNewContext(doc);
	if (context == NULL) {
		//printf("Error in xmlXPathNewContext\n");
		return NULL;
	}
	result = xmlXPathEvalExpression(xpath, context);
	xmlXPathFreeContext(context);
	if (result == NULL) {
		//printf("Error in xmlXPathEvalExpression\n");
		return NULL;
	}
	if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
		xmlXPathFreeObject(result);
               // printf("No result\n");
		return NULL;
	}
	return result;
}



#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}

#if 1

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
  fprintf(stderr, "call tcpback\n");



  char buf[1024];
  strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
    // connection described by a_tcp is established
    // here we decide, if we wish to follow this stream
    // sample condition: if (a_tcp->addr.dest!=23) return;
    // in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
      a_tcp->server.collect_urg++; // we want urgent data received by a
                                   // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
      a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
#endif
      fprintf (stderr, "%s established\n", buf);


      struct half_stream *hlf;
      hlf = &a_tcp->client; // analogical

      struct tm *tp;
    //  tp = localtime(&hlf->list->ts.tv_sec);

 	// fprintf(stderr, "first packet's arrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u, caplen=%d, len=%d\n", tp->tm_year+1900, tp->tm_mon+1,
 	//	   tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec,
	//	   nids_last_pcap_header->ts.tv_usec, nids_last_pcap_header->caplen, nids_last_pcap_header->len);



      return;
    }

  if (a_tcp->nids_state == NIDS_CLOSE)
    {

      struct half_stream *hlf;
	  hlf = &a_tcp->client; // analogical
	  write(2,hlf->data,hlf->count); // we print the newly arrived data
      fprintf(stderr, "\nclient count=%d, offset=%d", hlf->count, hlf->offset);
	  fprintf (stderr, "\n");


	  hlf = &a_tcp->server; // analogical
	  write(2,hlf->data,hlf->count); // we print the newly arrived data
	  fprintf(stderr, "\nserver count=%d, offset=%d", hlf->count, hlf->offset);
      fprintf (stderr, "\n");

      // connection has been closed normally
      fprintf (stderr, "%s closing\n", buf);

      struct tm *tp;
      tp = localtime(&(a_tcp->start_time.ts.tv_sec));
      fprintf(stderr, "first packet's arrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u\n", 
	  	       tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday, 
	  	       tp->tm_hour, tp->tm_min, tp->tm_sec,
	  	       a_tcp->start_time.ts.tv_usec);


      tp = localtime(&(a_tcp->end_time.ts.tv_sec));
      fprintf(stderr, "last packet's arrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u\n", 
	  	       tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday, 
	  	       tp->tm_hour, tp->tm_min, tp->tm_sec,
	  	       a_tcp->end_time.ts.tv_usec);

	  fprintf(stderr, "used time: %dms\n", 
	  	      (a_tcp->end_time.ts.tv_sec - a_tcp->start_time.ts.tv_sec)*1000 +  
	  	      (a_tcp->end_time.ts.tv_usec - a_tcp->start_time.ts.tv_usec)/1000);
      return;
   }

  if(a_tcp->nids_state == NIDS_RESET)
    {
	  struct half_stream *hlf;
	  	  hlf = &a_tcp->client; // analogical
	  	  write(2,hlf->data,hlf->count); // we print the newly arrived data
	        fprintf(stderr, "\nclient count=%d, offset=%d", hlf->count, hlf->offset);
	  	  fprintf (stderr, "\n");


	  	  hlf = &a_tcp->server; // analogical
	  	  write(2,hlf->data,hlf->count); // we print the newly arrived data
	  	  fprintf(stderr, "\nserver count=%d, offset=%d", hlf->count, hlf->offset);
	        fprintf (stderr, "\n");

      // connection has been closed by RST
      fprintf (stderr, "%s reset\n", buf);


      struct tm *tp;
      tp = localtime(&(a_tcp->start_time.ts.tv_sec));
      fprintf(stderr, "first packet's arrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u\n", 
	  	       tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday, 
	  	       tp->tm_hour, tp->tm_min, tp->tm_sec,
	  	       a_tcp->start_time.ts.tv_usec);


      tp = localtime(&(a_tcp->end_time.ts.tv_sec));
      fprintf(stderr, "last packet's arrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u\n", 
	  	       tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday, 
	  	       tp->tm_hour, tp->tm_min, tp->tm_sec,
	  	       a_tcp->end_time.ts.tv_usec);

	  fprintf(stderr, "used time: %dms\n", 
	  	      (a_tcp->end_time.ts.tv_sec - a_tcp->start_time.ts.tv_sec)*1000 +  
	  	      (a_tcp->end_time.ts.tv_usec - a_tcp->start_time.ts.tv_usec)/1000);
	  
      return;
    }

  if(a_tcp->nids_state == NIDS_TIMED_OUT)
     {
 	  struct half_stream *hlf;
 	  	  hlf = &a_tcp->client; // analogical
 	  	  write(2,hlf->data,hlf->count); // we print the newly arrived data
 	        fprintf(stderr, "\nclient count=%d, offset=%d", hlf->count, hlf->offset);
 	  	  fprintf (stderr, "\n");


 	  	  hlf = &a_tcp->server; // analogical
 	  	  write(2,hlf->data,hlf->count); // we print the newly arrived data
 	  	  fprintf(stderr, "\nserver count=%d, offset=%d", hlf->count, hlf->offset);
 	        fprintf (stderr, "\n");

       // connection has been closed by RST
       fprintf (stderr, "%s timeout\n", buf);


	   struct tm *tp;
	   tp = localtime(&(a_tcp->start_time.ts.tv_sec));
	   fprintf(stderr, "first packet's arrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u\n", 
				tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday, 
				tp->tm_hour, tp->tm_min, tp->tm_sec,
				a_tcp->start_time.ts.tv_usec);
	   
	   
	   tp = localtime(&(a_tcp->end_time.ts.tv_sec));
	   fprintf(stderr, "last packet's arrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u\n", 
				tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday, 
				tp->tm_hour, tp->tm_min, tp->tm_sec,
				a_tcp->end_time.ts.tv_usec);
	   
	   fprintf(stderr, "used time: %dms\n", 
			   (a_tcp->end_time.ts.tv_sec - a_tcp->start_time.ts.tv_sec)*1000 +  
			   (a_tcp->end_time.ts.tv_usec - a_tcp->start_time.ts.tv_usec)/1000);
       return;
     }


    if ( a_tcp->nids_state == NIDS_DATA)
    {
      // new data has arrived; gotta determine in what direction
      // and if it's urgent or not


	   // struct half_stream *hlf;
	  	//  hlf = &a_tcp->client; // analogical
	  	 // write(2,hlf->data,hlf->count); // we print the newly arrived data
	    //    fprintf(stderr, "\nclient count=%d, offset=%d, count_new=%d", hlf->count, hlf->offset, hlf->count_new);
	  	 // fprintf (stderr, "\n");


	  	 // hlf = &a_tcp->server; // analogical
	  	  //write(2,hlf->data,hlf->); // we print the newly arrived data
	  	  //fprintf(stderr, "\nserver count=%d, offset=%d, count_new=%d", hlf->count, hlf->offset, hlf->count_new);
	        //fprintf (stderr, "\n");

	  nids_discard(a_tcp, 0);

	  return;

      struct half_stream *hlf;

      if (a_tcp->server.count_new_urg)
      {
        // new byte of urgent data has arrived
        strcat(buf,"(urgent->)");
        buf[strlen(buf)+1]=0;
        buf[strlen(buf)]=a_tcp->server.urgdata;
        write(1,buf,strlen(buf));
        return;
      }
      // We don't have to check if urgent data to client has arrived,
      // because we haven't increased a_tcp->client.collect_urg variable.
      // So, we have some normal data to take care of.
      if (a_tcp->client.count_new)
	{
          // new data for client
	  hlf = &a_tcp->client; // from now on, we will deal with hlf var,
                                // which will point to client side of conn
	  strcat (buf, "(<-)"); // symbolic direction of data
	}
      else
	{
	  hlf = &a_tcp->server; // analogical
	  strcat (buf, "(->)");
	}
    fprintf(stderr,"%s",buf); // we print the connection parameters
                              // (saddr, daddr, sport, dport) accompanied
                              // by data flow direction (-> or <-)

   write(2,hlf->data,hlf->count_new); // we print the newly arrived data

    }
  return ;
}


#else if

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{

  char buf[102400];
  strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
    // connection described by a_tcp is established
    // here we decide, if we wish to follow this stream
    // sample condition: if (a_tcp->addr.dest!=23) return;
    // in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
      a_tcp->server.collect_urg++; // we want urgent data received by a
                                   // server
//#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
      a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
//#endif
      fprintf (stderr, "%s established\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_CLOSE)
    {
      // connection has been closed normally
      fprintf (stderr, "%s closing\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_RESET)
    {
      // connection has been closed by RST
      fprintf (stderr, "%s reset\n", buf);
      return;
    }

  if (a_tcp->nids_state == NIDS_DATA)
    {
      // new data has arrived; gotta determine in what direction
      // and if it's urgent or not

      struct half_stream *hlf;

      if (a_tcp->server.count_new_urg)
      {
        // new byte of urgent data has arrived 
        strcat(buf,"(urgent->)");
        buf[strlen(buf)+1]=0;
        buf[strlen(buf)]=a_tcp->server.urgdata;
        write(1,buf,strlen(buf));
        return;
      }

      if(a_tcp->client.count_new_urg)
            {
              // new byte of urgent data has arrived
              strcat(buf,"(urgent<-)");
              buf[strlen(buf)+1]=0;
              buf[strlen(buf)]=a_tcp->client.urgdata;
              write(1,buf,strlen(buf));
              return;
            }
      // We don't have to check if urgent data to client has arrived,
      // because we haven't increased a_tcp->client.collect_urg variable.
      // So, we have some normal data to take care of.
      if (a_tcp->client.count_new)
	{
          // new data for client
	  hlf = &a_tcp->client; // from now on, we will deal with hlf var,
                                // which will point to client side of conn
	  strcat (buf, "(<-)"); // symbolic direction of data
	}
      else
	{
	  hlf = &a_tcp->server; // analogical
	  strcat (buf, "(->)");
	}
    fprintf(stderr,"%s",buf); // we print the connection parameters
                              // (saddr, daddr, sport, dport) accompanied
                              // by data flow direction (-> or <-)

   write(2,hlf->data,hlf->count_new); // we print the newly arrived data
      
    }
  return ;
}

#endif

int 
main ()
{
  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;


  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  nids_register_tcp (tcp_callback);
  nids_run ();
  return 0;
}

