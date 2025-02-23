from django.contrib import admin

from .models import Post, PostComment, PostLike, CommentLike

# Register your models here.

class PostInline(admin.TabularInline):
    model = Post
    extra = 1

class PostCommentInline(admin.StackedInline):
    model = PostComment
    extra = 1

class PostAdmin(admin.ModelAdmin):
    list_display = ('author', 'caption', 'id')
    search_fields = ('id', 'author__username', 'caption')
    inlines = [PostCommentInline]

class PostCommentAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'post', )
    search_fields = ('id', 'author__username', 'comment')



class PostLikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'post', 'created_at')
    search_fields = ('id', 'author__username')

class CommentLikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'comment', 'created_at')
    search_fields = ('id', 'author__username')

admin.site.register(Post, PostAdmin)
admin.site.register(PostComment, PostCommentAdmin)
admin.site.register(PostLike, PostLikeAdmin)
admin.site.register(CommentLike, CommentLikeAdmin)
