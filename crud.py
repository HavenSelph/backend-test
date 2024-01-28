from sqlalchemy.orm import Session
import models


def get_account_from_id(db: Session, account_id):
    return db.query(models.Account).filter(models.Account.id == account_id).first()


def get_account_from_username(db: Session, username):
    return db.query(models.Account).filter(models.Account.username == username).first()


def get_accounts(db: Session, skip=0, limit=100):
    return db.query(models.Account).offset(skip).limit(limit).all()


def create_account(db: Session, username, password):
    db_account = models.Account(username=username, password=password)
    db.add(db_account)
    db.commit()
    db.refresh(db_account)
    return db_account


def delete_account(db: Session, account_id):
    db_account = get_account_from_id(db, account_id)
    db.delete(db_account)
    db.commit()
    return db_account
