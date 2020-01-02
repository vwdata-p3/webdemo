import pep3_pb2_grpc
import pep3_pb2
import common
import sql

import threading

import codecs

# for database communication
from sqlalchemy import inspect, create_engine
from sqlalchemy import Column, Integer, String, DateTime, LargeBinary
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.schema import Sequence
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy.pool

import google.protobuf.json_format
import google.protobuf as pb

import grpc


Base = declarative_base()

class PepedFlow(Base):
    __tablename__ = 'peped_flows'
    flow_record_id      = Column(Integer, Sequence('peped_flows_flow_record_id_seq'), primary_key=True)
    start_time          = Column(Integer) #, nullable=False) / DateTime?
    end_time            = Column(Integer) 
    p_src_ip           = Column(LargeBinary)
    p_dst_ip           = Column(LargeBinary)
    src_port            = Column(Integer)
    dst_port            = Column(Integer)
    protocol            = Column(Integer)
    packets             = Column(Integer)
    bytes               = Column(Integer)

    def to_pb(self):
        r = pep3_pb2.FlowRecord()
        r.anonymous_part.start_time = self.start_time
        r.anonymous_part.end_time = self.end_time
        r.source_ip.data = self.p_src_ip
        r.source_ip.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM
        r.destination_ip.data = self.p_dst_ip
        r.destination_ip.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM
        r.anonymous_part.source_port = self.src_port
        r.anonymous_part.destination_port = self.dst_port
        r.anonymous_part.protocol = self.protocol
        r.anonymous_part.number_of_packets = self.packets
        r.anonymous_part.number_of_bytes = self.bytes
        return r
    def validate(self):
        assert(self.packets > 0),"Flow can not have 0 packets"
        assert(self.bytes > 0),"Flow can not have 0 bytes"
        #TODO: are there any assertions we can do on the format/size of the triples?

    def print(self):
        print(self.__header__())
        print(self)
        
    def __header__(self):
        return "{: >39} -> {: <39} {: <5} {: <5} -> {: <5} {: <10} {: <10}".format(
                "src", "dst", "proto", "src_p", "dst_p", "bytes", "packets")

    def __str__(self):
        return "{!s: >39} -> {!s: <39} {: <5} {: <5} -> {: <5} {: <10} {: <10}".format(
            hextail(self.p_src_ip),
            hextail(self.p_dst_ip),
            self.protocol,
            self.src_port,
            self.dst_port,
            self.bytes,
            self.packets
        )

class Database(pep3_pb2_grpc.DatabaseServicer):
    def __init__(self, pep):
        self.pep = pep

        econf = self.pep.config.engine
        
        poolclass = None
        if econf.poolclass!="":
            poolclass = getattr(sqlalchemy.pool, econf.poolclass)

        try:
            self.engine = create_engine(econf.uri, poolclass=poolclass,
                    connect_args=econf.connect_args)

            if self.pep.config.engine.create_tables:
                Base.metadata.create_all(self.engine)

            inspector = inspect(self.engine)
            session_factory = sessionmaker(bind=self.engine)
            self.Session = scoped_session(session_factory)
        except Exception as e:
            raise Exception(f"DB error: {e}")

        # setup self.db_desc used by sql.check_query
        self.db_desc = Database.load_db_desc_from(self.pep.global_config)
                
 
    @staticmethod
    def load_db_desc_from(global_config):
        db_desc = {}
        for table_name, table_desc in global_config.db_desc.items():
            db_desc[table_name] = {}
            for column_name, value in table_desc.columns.items():
                db_desc[table_name][column_name] = value
        return db_desc


    def Store(self, request_it, context):
        common.authenticate(context,
                must_be_one_of=[b"PEP3 storage_facility"])
        
        for request in request_it:
            local_session = self.Session()
            local_session.bulk_insert_mappings(PepedFlow, [dict(
                start_time  = record.anonymous_part.start_time,
                end_time    = record.anonymous_part.end_time,
                p_src_ip    = record.source_ip.data,
                p_dst_ip    = record.destination_ip.data,
                src_port    = record.anonymous_part.source_port,
                dst_port    = record.anonymous_part.destination_port,
                protocol    = record.anonymous_part.protocol,
                packets     = record.anonymous_part.number_of_packets,
                bytes       = record.anonymous_part.number_of_bytes
            ) for record in request.records])
            local_session.commit()
            yield pep3_pb2.StoreFeedback(stored_id=request.id)

        
    def Query(self, query, context): 
        common.authenticate(context,
                must_be_one_of=[b"PEP3 storage_facility"])

        local_session = self.Session()

        params = {}
        param_desc = {}

        for name, value in query.parameters.items():
            params[name], param_desc[name] \
                    = common.value_to_object_and_type(value)

        try:
            result_desc = sql.check_query(self.db_desc, param_desc, 
                    query.query)
        except sql.InvalidQuery as e:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    f"invalid query: {e}")

        sql_rows = local_session.execute(query.query, params)

        pb_rows = pep3_pb2.Rows()

        for sql_row in sql_rows:
            assert(len(sql_row)==len(result_desc))

            pb_row = pb_rows.rows.add()

            for i in range(len(result_desc)):
                pb_cell = pb_row.cells.add()
                common.object_and_type_to_value(pb_cell, 
                        sql_row[i], result_desc[i])

            if len(pb_rows.rows)==32:
                yield pb_rows
                pb_rows.Clear()
        if len(pb_rows.rows)>0:
            yield pb_rows

def hextail(data):
    return codecs.encode(data, 'hex_codec').decode("utf-8")[-8:]
