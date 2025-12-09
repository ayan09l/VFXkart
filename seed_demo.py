# seed_demo.py - run once to populate demo seller + products
from app import app, db, Seller, SellerUser, Product, ProductImage, make_unique_filename, UPLOAD_FOLDER
from werkzeug.security import generate_password_hash
import os, shutil, uuid

def seed():
    with app.app_context():
        db.create_all()

        s = Seller(name="Demo Seller", brand="VFX Demo", email="demo@seller.local", approved=True)
        db.session.add(s); db.session.flush()

        demo_user = SellerUser(username="demouser", email="demo@seller.local",
                               password_hash=generate_password_hash("demopass"),
                               seller_profile_id=s.id)
        db.session.add(demo_user)
        db.session.commit()

        sample_titles = [
            "Cinematic Explosion Pack",
            "Realistic Rain Drops",
            "Magic Smoke & Fog",
            "Neon Futuristic HUD",
            "Hologram Overlays",
            "Lens Flares Pro",
            "Film Grain & Vignette",
            "Motion Blur FX Bundle"
        ]

        for i, t in enumerate(sample_titles, start=1):
            p = Product(
                seller_id=demo_user.id,
                title=t,
                price=f"{99 + i*50}",
                description=f"Demo product {i} - high quality VFX pack."
            )
            db.session.add(p); db.session.flush()

            placeholder = "placeholder.jpg"
            if os.path.exists(os.path.join(UPLOAD_FOLDER, placeholder)):
                img = ProductImage(product_id=p.id, filename=placeholder, thumb=placeholder)
                db.session.add(img)

        db.session.commit()
        print("Demo data seeded. Seller user: demouser / demopass")

if __name__ == "__main__":
    seed()
