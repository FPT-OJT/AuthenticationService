local exists = redis.call('EXISTS', KEYS[1])
if exists == 0 then
    return -1
end

local current_status = redis.call('HGET', KEYS[1], ARGV[1])

if not current_status then
    return 0
end

if current_status ~= ARGV[2] then
    return 0
end

redis.call('HSET', KEYS[1], ARGV[1], '1')

return 1
