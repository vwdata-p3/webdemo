import ed25519
import common

# Convenience functions for when all secrets are available
# (such as during tests and benchmarks).

def secrets_by_shard(secrets):
    result = {}
    for peer_secrets in secrets.peers.values():
        for shard, shard_secrets in peer_secrets.by_shard.items():
            if shard not in result:
                result[shard] = shard_secrets
    return result

def public_key(secrets, common_name, domain):
    return ed25519.Point.B_times(private_key(secrets, common_name, domain))

def private_key(secrets, common_name, domain):
    e = ed25519.scalar_unpack(common.sha256(common_name))
    x = 1

    for shard, shard_secrets in secrets_by_shard(secrets).items():
        x *= ed25519.scalar_unpack( shard_secrets.by_domain[domain]\
                .private_master_key )
        x %= ed25519.l
        x *= pow(ed25519.scalar_unpack(
            shard_secrets.by_domain[domain].key_component_secret), e, ed25519.l)
        x %= ed25519.l

    return x
        

