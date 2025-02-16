from django.db.models.signals import pre_delete
from django.dispatch import receiver
from django.db.models import Sum
from .models import Advertisement, UserWallet, UserTransaction


@receiver(pre_delete, sender=Advertisement)
def refund_user_on_delete(sender, instance, **kwargs):
    try:
        # Update the advertisement title in transactions to retain context after deletion
        UserTransaction.objects.filter(advertisement=instance).update(advertisement_title=instance.title)

        # Attempt to retrieve the user's wallet
        user_wallet = UserWallet.objects.get(user=instance.user)

        # Calculate the refund amount
        refund_amount = instance.remaining_budget

        # Refund the remaining budget to the user's wallet
        user_wallet.balance += refund_amount
        user_wallet.save()

        # Log the refund transaction
        transaction = UserTransaction.objects.create(
            user=instance.user,
            advertisement=None,  # Set advertisement to None since it's being deleted
            transaction_type='refund',
            advertisement_title=instance.title,  # Retain the title for reference
            amount=refund_amount,
            status='approved'
        )
        print(f"Created transaction: {transaction.id} for advertisement: {transaction.advertisement_title}")

        # Recalculate total earnings and total spending
        update_user_wallet_totals(user_wallet)

    except UserWallet.DoesNotExist:
        print(f"User wallet not found for user: {instance.user.username}")
    except Exception as e:
        print(f"An error occurred during the refund process: {str(e)}")


def update_user_wallet_totals(user_wallet):
    # Calculate total earnings
    total_earning = UserTransaction.objects.filter(
        user=user_wallet.user,
        transaction_type='earn'
    ).aggregate(Sum('amount'))['amount__sum'] or 0.00

    # Calculate total spending
    total_spending = UserTransaction.objects.filter(
        user=user_wallet.user,
        transaction_type='spend'
    ).aggregate(Sum('amount'))['amount__sum'] or 0.00

    # Update the wallet fields
    user_wallet.total_earning = total_earning
    user_wallet.total_spending = total_spending
    user_wallet.save()

    print(
        f"Updated wallet totals for user {user_wallet.user.username}: Total Earning = {total_earning}, Total Spending = {total_spending}")
