import sys
from censys.search import CensysHosts

h = CensysHosts()
queryStatement = "same_service(services.port: 8883 and services.service_name: MQTT)"    # change query statement
query = h.search(queryStatement, per_page=25, pages=1)   # change pages number
for page in query:
    for host in page:
        for service in host["services"]:
            # print(service)
            if (service["service_name"] == "MQTT" and service["port"] == 8883):  #   change service name and port for protocol
                a = ""
                a = a + str(host["ip"]) + ":" + str(service["port"])
                print(a)

# Queries:
#     MQTT:   "same_service(services.port: 8883 and services.service_name: MQTT)"   #737
#     AMQP:   "same_service(services.port: 5671 and services.service_name: AMQP)"   #375
#     CoAP:   "same_service(services.port: 5684 and services.service_name: COAP)"   #82
#     DDS:    "Not Supported"
#     XMPP:   "same_service(services.port: 5269 and services.service_name: XMPP)"   #880    *server - server
#             "same_service(services.port: 5222 and services.service_name: XMPP)"   #1150   *client - server
#             "me_service((services.port: 5222 or services.port: 5269) and services.service_name: XMPP)" #1190
