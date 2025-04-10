# Item-related endpoints

from fastapi import APIRouter, HTTPException, Depends
from models.models import Item, User
from db.db import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from core.security import get_current_user_or_m2m, get_current_user
from pydantic import BaseModel

router = APIRouter()


class ItemCreate(BaseModel):
    name: str


@router.post("/items/")
async def add_item(item_data: ItemCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    new_item = Item(name=item_data.name, owner_id=user.id)
    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)  # Ensure new_item.id is populated
    return {"message": "Item added successfully", "item_id": new_item.id}

@router.get("/items/{item_id}")
async def read_item(
    item_id: int,
    user_or_m2m: dict = Depends(get_current_user_or_m2m),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Item).filter(Item.id == item_id))
    item = result.scalars().first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # Allow access if it's an M2M request
    # If regular user, check ownership
    if isinstance(user_or_m2m, dict) and user_or_m2m.get("m2m"):
        return item  # M2M Client can read all items

    # Allow access if the user owns the item
    if user_or_m2m.id == item.owner_id:
        return item

    raise HTTPException(status_code=403, detail="Access denied")

@router.put("/items/{item_id}")
async def update_item(
    item_id: int,
    data: ItemCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Item).filter(Item.id == item_id))
    item = result.scalars().first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    item.name = data.name
    await db.commit()
    await db.refresh(item)
    return item


@router.delete("/items/{item_id}")
async def delete_item(
    item_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Item).filter(Item.id == item_id))
    item = result.scalars().first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    await db.delete(item)
    await db.commit()
    return {"detail": "Item deleted"}
