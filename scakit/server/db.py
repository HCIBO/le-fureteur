from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_config


class Base(DeclarativeBase):
    pass


_engine = None
_Session = None


def engine():
    global _engine, _Session
    if _engine is None:
        url = get_config().database_url
        kw = {"connect_args": {"check_same_thread": False, "timeout": 30}} if url.startswith("sqlite") else \
            {"pool_pre_ping": True}
        _engine = create_engine(url, **kw)
        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def _pragma(dbapi_conn, _):
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()
        _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def SessionLocal() -> Session:
    engine()
    return _Session()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models
    Base.metadata.create_all(engine())
    _add_missing_columns()
    _seed_tags()


def _seed_tags() -> None:
    from .models import DEFAULT_TAGS, Tag
    db = SessionLocal()
    try:
        have = {t.name for t in db.query(Tag).filter(Tag.builtin.is_(True))}
        for name, color in DEFAULT_TAGS:
            if name not in have:
                db.add(Tag(name=name, color=color, builtin=True))
        db.commit()
    finally:
        db.close()


def _add_missing_columns() -> None:
    from sqlalchemy import inspect, text
    eng = engine()
    insp = inspect(eng)
    with eng.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                ddl = col.type.compile(dialect=eng.dialect)
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {ddl}'))


def reset_for_tests() -> None:
    global _engine, _Session
    if _engine is not None:
        _engine.dispose()
    _engine = _Session = None
