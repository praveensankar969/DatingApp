using API.Entities;

namespace API.Interfaces{
    public interface ITokenInterface{
        string CreateToken(AppUser user);
    }
}