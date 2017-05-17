from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="El Bundy", email="elbundy@elbundy.com",
             picture='http://vignette1.wikia.nocookie.net/marriedwithchildren/images/b/b8/Al_Bundy.jpg/revision/latest?cb=20141207170838')
session.add(User1)
session.commit()

# Catalog-ID Soccer
catalog1 = Catalog(user_id=1, name="Soccer")

session.add(catalog1)
session.commit()

item2 = Item(user_id=1, name="Shoes", description="To hit the ball perfect.",
                     catalog=catalog1)

session.add(item2)
session.commit()


item1 = Item(user_id=1, name="Ball", description="The most important part.",
                     catalog=catalog1)

session.add(item1)
session.commit()

# Catalog-ID Snowboard
catalog2 = Catalog(user_id=1, name="Snowboarding")

session.add(catalog2)
session.commit()

item2 = Item(user_id=1, name="Goggles", description="To see it better.",
                     catalog=catalog2)

session.add(item2)
session.commit()


item1 = Item(user_id=1, name="Snowboard", description="The board to rule them all.",
                     catalog=catalog2)

session.add(item1)
session.commit()


print "added catalog items!"