import pathlib
import argparse
import os
import datetime
import json
import traceback
import xmltodict
import re
from elasticsearch import Elasticsearch, helpers
from elasticsearch.helpers import streaming_bulk
import sys
import logging
import time

class PlasoToELK:
    """
       Class MaximumPlasoParser
       MPP or MaximumPlasoParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, path_to_timeline, case_name=None, elk_ip="localhost", elk_port="9200") -> None:
        self.path_to_timeline = path_to_timeline
        self.case_name = case_name
        self.elk_ip = elk_ip
        self.elk_port = elk_port
        self.id = 1
        self.current_date = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S")
        self.work_dir = "./temp_{}".format(self.current_date)
        #self.work_dir = "./temp"
        self.initialise_working_directories()
        self.line_counter = 0
        self.file_name_inc = 0


        #self.es = Elasticsearch("https://{}:{}".format(elk_ip, elk_port), basic_auth=('elastic', 'changeme'), ca_certs=False, verify_certs=False)
        self.es_hosts = ["https://localhost:9200"]
        self.es_api_user = 'elastic'
        self.es_api_password = 'changeme'
        self.index_name = self.case_name
        self.chunk_size = 10000
        self.errors_before_interrupt = 5
        self.refresh_index_after_insert = False
        self.max_insert_retries = 3
        self.yield_ok = False  # if set to False will skip successful documents in the output
        self.errors_count = 0

        self.es = Elasticsearch(
            self.es_hosts,
            basic_auth=(self.es_api_user, self.es_api_password),
            ca_certs=False,
            verify_certs=False,
            ssl_show_warn=False
        )

    def initialise_working_directories(self):
        """
        To create directories where the results will be written
        :return:
        """
        try:
            os.makedirs(self.work_dir, exist_ok=True)
            print("result directory is located at : {}".format(self.work_dir))
        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))
        
    def identify_type_artefact_by_parser(self, line):
        """
        Function to indentify an artefact type depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }
        for key, value in d_regex_type_artefact.items():
            if re.search(value, line.get("parser")):
                return key

    def convert_epoch_to_date(self, epoch_time):
        """
        Function to convert an epoch time (nanoseconds) into date and time.
        Split into 2 variable date and time
        :param epoch_time: (int) epoch time to be converted
        :return:
        (str) date in format %Y-%m-%d
        (str) time in format %H:%M:%S
        """
        dt = datetime.datetime.fromtimestamp(epoch_time / 1000000).strftime('%Y-%m-%dT%H:%M:%S.%f')
        return dt

    def microsoft_filetime_to_dt(self, ft):
        EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
        HUNDREDS_OF_NANOSECONDS = 10000000
        """Converts a Microsoft filetime number to a Python datetime. The new
        datetime object is time zone-naive but is equivalent to tzinfo=utc.
            filetime_to_dt(116444736000000000)
        datetime.datetime(1970, 1, 1, 0, 0)
            filetime_to_dt(128930364000000000)
        datetime.datetime(2009, 7, 25, 23, 0)
        """
        if type(ft) is not int:
            return EPOCH_AS_FILETIME
        else:
            return ft - EPOCH_AS_FILETIME
        # return datetime.datetime.fromtimestamp((ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS).strftime('%Y-%m-%dT%H:%M:%S.%f')

    def write_to_file(self, file_out, content):
        try:
            with open(file_out, "a+") as file_out_path:
                json.dump(content, file_out_path)
                file_out_path.write("\n")
        except:
            print(traceback.format_exc())

    def get_event(self):
        
        """
        Main function to parse the plaso timeline
        :param None
        :return: None
        """
        with open(self.path_to_timeline) as timeline:
            for line in timeline:
                try:

                    #file_out_name = "timeline_part_{}".format(self.file_name_inc)
                    file_out_name = "timeline_formated.json"
                    file_out = os.path.join(self.work_dir, file_out_name)
                    d_line = json.loads(line)
                    artefact_type = self.identify_type_artefact_by_parser(d_line)
                    if artefact_type == "evtx":
                        self.format_evt_from_xml(d_line, file_out)
                        self.line_counter += 1
                    else:
                        self.format_all(d_line, file_out)
                        self.line_counter +=1
                    '''
                    if self.line_counter == 60000:
                        self.line_counter = 0
                        self.file_name_inc +=1
                    '''

                except:
                    print("could not load json line, skipping line")
                    print(traceback.format_exc())
                    exit(1)
            return file_out

    def format_evt_from_xml(self, event, file_out):
        """
        Function to format content of evtx result provided by plaso.
        The function will get the interesting information from the xml string and add them properly to the json res
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        evt_as_json = ""
        formated_event = event
        timestamp_formated = self.convert_epoch_to_date(event.get("timestamp", 946684800000))
        formated_event["timestamp"] = timestamp_formated

        date_time_cat = event.get("date_time")
        if type(date_time_cat) == dict:
            ms_date = date_time_cat.get("timestamp", 946684800000)  # set default to 1 jan of 2000
            formated_date_time_ts = self.microsoft_filetime_to_dt(ms_date)
            event["date_time"]["timestamp"] = formated_date_time_ts

        try:
            if event.get("xml_string"):
                evt_as_xml = event.get("xml_string")
                evt_as_json = xmltodict.parse(evt_as_xml)
        except:
            print("error parsing xml")
            self.write_to_file(file_out, formated_event)
            return

        try:
            if evt_as_json and isinstance(evt_as_json, dict):
                all_evt = evt_as_json.get("Event")  # .get("EventData", {}).get("Data")
                if all_evt and isinstance(all_evt, dict):
                    event_data = all_evt.get("EventData")
                    if event_data and isinstance(event_data, dict):
                        new_data = {}
                        data_list = event_data.get("Data")
                        if data_list and isinstance(data_list, list):
                            for data in data_list:
                                if isinstance(data, dict):
                                    new_data.update({data.get("@Name", "-"): data.get("#text", "-")})
                        evt_as_json["Event"]["EventData"] = new_data

                formated_event["EVENT_PARSED"] = evt_as_json

            self.write_to_file(file_out, formated_event)
        except:
            print(traceback.format_exc())
            print(event)
            exit(1)
        #print(json.dumps(formated_event, indent=4))

    def format_all(self, event, file_out):
        try:
            timestamp_formated = self.convert_epoch_to_date(event.get("timestamp", 946684800000)) # set default to 1 jan of 2000
            event["timestamp"] = timestamp_formated
            date_time_cat = event.get("date_time")
            if type(date_time_cat) == dict:
                ms_date = date_time_cat.get("timestamp", 946684800000) # set default to 1 jan of 2000
                formated_date_time_ts = self.microsoft_filetime_to_dt(ms_date)
                event["date_time"]["timestamp"] = formated_date_time_ts
        except:
            #print(json.dumps(event, indent = 4))
            print(traceback.format_exc())
            print("error converting ms timestamp")

        self.write_to_file(file_out, event)
        #print(json.dumps(event, indent=4))

    def send_one_to_elk(self,event):
        response = self.elk_client.index(
            index = self.case_name,
            id = self.id,
            document = event
        )
        print(response)
        print("sent to elk !")
        self.id += 1

    def data_generator(self, file_name):
        f = open(file_name)
        for line in f:
            yield {**json.loads(line), **{
                "_index": self.index_name,
                "_id": self.id
            }}
            self.id += 1

    def send_file_to_elk(self, file_name):
        for ok, result in streaming_bulk(self.es, self.data_generator(file_name), chunk_size=self.chunk_size,
                                         refresh=self.refresh_index_after_insert,
                                         max_retries=self.max_insert_retries, yield_ok=self.yield_ok):
            if ok is not True:
                logging.error('Failed to import data')
                logging.error(str(result))
                self.errors_count += 1

                if self.errors_count == self.errors_before_interrupt:
                    logging.fatal('Too many import errors, exiting with error code')
                    exit(1)



def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse a json plaso timeline'))


    argument_parser.add_argument("-o", "--output", action="store",
                                 required=False, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    argument_parser.add_argument("-f", "--file", action="store",
                                 required=True, dest="file", default=None,
                                 help="plaso timeline json to parse")

    argument_parser.add_argument("-p", "--parse", action="store_true",
                                 required=False, dest="parse", default=None,
                                 help="set to parse timeline, must be used with -f option")

    argument_parser.add_argument("-s", "--send", action="store_true",
                                 required=False, dest="send", default=None,
                                 help="set to send to elk, must be used with -f and -p option")

    argument_parser.add_argument("--file_to_elk", action="store",
                                 required=False, dest="file_to_elk", default=None,
                                 help="send parsed file to elk, must provide path to file")




    return argument_parser


def get_formated_time(duration_seconds):
    hours = int(duration_seconds // 3600)
    minutes = int((duration_seconds % 3600) // 60)
    seconds = duration_seconds % 60
    return "{}-{}-{}".format(hours, minutes, seconds)

if __name__ == '__main__':


    parser = parse_args()
    args = parser.parse_args()
    plaso_to_elk = PlasoToELK(args.file, "test_hugo")
    if args.file and args.parse:
        start_time = time.time()
        print("Started formating timeline at:", datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
        file_out = plaso_to_elk.get_event()
        print("Finished formating timeline in {}".format(get_formated_time(time.time() - start_time)))
        if args.send:
            start_time = time.time()
            print("Started formating timeline at:", datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
            plaso_to_elk.send_file_to_elk(file_out)
            print("Finished sending logs to ELK in {}".format(get_formated_time(time.time() - start_time)))

    if args.file_to_elk:
        start_time = time.time()
        print("Started sending logs to elk at:", datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
        plaso_to_elk.send_file_to_elk(args.file_to_elk)
        print("Finished sending logs to ELK in  {}".format(get_formated_time(time.time() - start_time)))



    
 

    ## 65 000 lines ~= 100 mo

